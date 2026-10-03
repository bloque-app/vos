//! Multi-agent node — runs multiple services on separate threads.
//!
//! Each agent/service gets its own [`VosRuntime`] on a dedicated thread.
//! All services on a node share a **global ID namespace** with a common
//! node prefix:
//!
//! ```text
//! ServiceId = [node_prefix: 16 bits][local_id: 16 bits]
//! ```
//!
//! Cross-agent transfers are routed by the node: if the target's prefix
//! matches this node, the message is delivered locally. Otherwise it's
//! forwarded to the network layer (future).

use std::collections::HashMap;
// HashSet is only used by the CRDT/Raft sync+replication paths (peer-set
// and sync-head dedup), which need both features; OnceLock backs the
// network-only manifest slot. Gating each to exactly the features its
// users require keeps every reduced-feature build warning-clean.
#[cfg(all(feature = "storage", feature = "network"))]
use std::collections::{BTreeMap, BTreeSet, HashSet};
#[cfg(feature = "network")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::abi::service::ServiceId;
use crate::runtime::VosRuntime;

/// A message routed between agents via the node.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: ServiceId,
    pub to: ServiceId,
    pub payload: Vec<u8>,
    /// Exact Noise-authenticated source of an inbound canonical service frame.
    /// Local and not-yet-networked envelopes carry `None`.
    pub authenticated_source_peer: Option<Vec<u8>>,
    /// Exact destination selected from a trusted external-actor binding.
    /// This is directionally distinct from the authenticated source because
    /// a compact route may collide with this node's own 16-bit prefix.
    pub destination_peer: Option<Vec<u8>>,
}

/// Handle to a running agent thread.
struct AgentHandle {
    join: Option<thread::JoinHandle<AgentResult>>,
}

/// Result returned when an agent thread completes.
///
/// `panics` counts PVM-side panics during refine. `error` is set
/// when the host itself failed unrecoverably — strategy build,
/// replay rebuild divergence, commit failure — and we tore the
/// agent down rather than continuing with corrupt state.
pub struct AgentResult {
    pub id: ServiceId,
    pub panics: u32,
    pub error: Option<String>,
}

/// Registration failures for one guest-owned service root service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRegistrationError {
    ServiceRouteOccupied(ServiceId),
    ActorAlreadyRegistered(crate::service::ActorId),
    CorruptServiceStore,
    LogicalTimeslotExhausted,
    LogicalTimeslotUnavailable,
    LogicalTimeslotRegressed,
}

/// Authenticated mapping from a canonical actor identity to its physical
/// node route and owning root service. Transport checks both fields; an
/// `ActorId` collision on another root must never redirect a committed call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorRoute {
    route: u32,
    service: crate::service::ServiceIdentity,
    consistency: crate::service::ConsistencyMode,
    /// Exact Raft group serving a locally attached root. Compact route
    /// prefixes are insufficient for authenticating a redirected leader.
    replication_id: Option<[u8; 32]>,
    /// Set only for the daemon-validated reserved authority installation.
    /// A method name alone never opts an application root into host protocols.
    is_role_authority: bool,
    /// End-to-end host wait for one typed invocation. Raft roots derive this
    /// from their proposal budget so the voter-authentication, read-barrier,
    /// commit, transport, and execution stages share one sufficient deadline.
    invoke_timeout: Duration,
    /// Full Noise-authenticated libp2p PeerId bytes for remote routes.
    /// Local routes never cross the network bridge and therefore use `None`.
    authenticated_peer: Option<Vec<u8>>,
}

/// One Raft transport destination whose current leader is resolved outside
/// the global envelope router. The replication incarnation prevents a stale
/// cache entry surviving reinstall; the local route suffix distinguishes
/// roots when one group hosts more than one service route.
#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RaftTransportResolutionKey {
    replication_id: [u8; 32],
    local_id: u16,
}

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug, Clone)]
enum RaftTransportResolution {
    Pending {
        generation: u64,
        candidate_cursor: usize,
        until: Instant,
    },
    Resolved {
        peer: libp2p::PeerId,
        route: ServiceId,
        candidate_cursor: usize,
        until: Instant,
    },
    Backoff {
        candidate_cursor: usize,
        until: Instant,
    },
}

#[cfg(all(feature = "network", feature = "storage"))]
impl RaftTransportResolution {
    fn candidate_cursor(&self) -> usize {
        match self {
            Self::Pending {
                candidate_cursor, ..
            }
            | Self::Resolved {
                candidate_cursor, ..
            }
            | Self::Backoff {
                candidate_cursor, ..
            } => *candidate_cursor,
        }
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
type RaftTransportResolutions =
    Arc<Mutex<HashMap<RaftTransportResolutionKey, RaftTransportResolution>>>;

const SERVICE_LOCAL_INVOKE_TIMEOUT: Duration = Duration::from_secs(10);

fn ingress_invocation_id(
    subject: crate::service::SubjectId,
    target: crate::service::ActorId,
    ingress: &str,
    key: &str,
) -> crate::service::InvocationId {
    crate::service::InvocationId::for_ingress_idempotency(subject, target, ingress, key.as_bytes())
}

fn receive_service_invocation_reply(
    reply: &mpsc::Receiver<Vec<u8>>,
    proof_requested: bool,
    deadline: Instant,
) -> Result<Vec<u8>, crate::actors::client::ClientError> {
    if proof_requested {
        reply
            .recv()
            .map_err(|_| crate::actors::client::ClientError::Unreachable)
    } else {
        reply
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| crate::actors::client::ClientError::Unreachable)
    }
}

/// Await the terminal result of work already accepted by a root service.
///
/// Built-in ingress dispatches this wait on its bounded blocking pool. Once
/// the root owns the request there is no cancellation boundary: timing out
/// here would drop the reply channel while the invocation can still commit.
/// A subsequent HTTP query would then use a fresh invocation identity and can
/// build an unbounded queue of abandoned work behind a slow authorization or
/// recovery pass. Retaining the original receiver lets the root finish or
/// disconnect and keeps publication acknowledgement tied to the real caller.
fn receive_service_ingress_reply(
    reply: &mpsc::Receiver<Vec<u8>>,
) -> Result<Vec<u8>, crate::actors::client::ClientError> {
    reply
        .recv()
        .map_err(|_| crate::actors::client::ClientError::Unreachable)
}

fn send_service_ingress(
    route: &mpsc::Sender<InvokeRequest>,
    ingress: &[u8],
    caller: crate::actors::Caller,
) -> Result<mpsc::Receiver<Vec<u8>>, crate::actors::client::ClientError> {
    let (reply_tx, reply_rx) = mpsc::channel();
    route
        .send(InvokeRequest {
            caller,
            space_role: None,
            actor_local_role: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: None,
            native_call: None,
            msg: ingress.to_vec(),
            reply: ReplyChannel::Sync(reply_tx),
            chain: Vec::new(),
        })
        .map_err(|_| crate::actors::client::ClientError::Unreachable)?;
    Ok(reply_rx)
}

fn send_service_system_ingress(
    route: &mpsc::Sender<InvokeRequest>,
    ingress: &[u8],
) -> Result<mpsc::Receiver<Vec<u8>>, crate::actors::client::ClientError> {
    send_service_ingress(route, ingress, crate::actors::Caller::System)
}

/// Resolve an attested Raft invocation without turning an ambiguous transport
/// failure into a caller-visible failure. `ingress` is the already-committed
/// invocation wire, including its stable invocation ID. Every remote attempt
/// and every local status/recovery redrive receives those exact bytes.
///
/// Proof production has no cancellation contract. Once the request has been
/// handed to a remote leader, a disconnected request-response channel or its
/// internal timeout cannot prove that Apply did not commit. Re-entering the
/// local Raft route lets the current leader either finish the same request or
/// recover its durable dedup result.
#[cfg(all(feature = "network", feature = "storage"))]
enum AttestedRedriveAttempt {
    /// No transport accepted the request, so this attempt cannot have
    /// committed it.
    NotSent,
    /// A transport accepted the request but lost its terminal response.
    Ambiguous,
    Reply(Vec<u8>),
}

#[cfg(all(feature = "network", feature = "storage"))]
fn receive_service_attested_with_exact_redrive<Remote, Local, Backoff>(
    ingress: &[u8],
    mut redirect: RaftRedirect,
    mut remote_attempt: Remote,
    mut local_redrive: Local,
    mut backoff: Backoff,
) -> Result<Vec<u8>, crate::actors::client::ClientError>
where
    Remote: FnMut(RaftRedirect, &[u8]) -> AttestedRedriveAttempt,
    Local: FnMut(&[u8]) -> AttestedRedriveAttempt,
    Backoff: FnMut(),
{
    let mut outcome_ambiguous = false;
    loop {
        match remote_attempt(redirect, ingress) {
            AttestedRedriveAttempt::NotSent => {}
            AttestedRedriveAttempt::Ambiguous => outcome_ambiguous = true,
            AttestedRedriveAttempt::Reply(envelope) => {
                if let Some(next) = decode_service_raft_redirect(&envelope) {
                    redirect = next;
                    backoff();
                    continue;
                }
                match decode_host_invoke_envelope(&envelope) {
                    Ok(reply) => return Ok(reply),
                    // The network dispatcher represents its own expired
                    // blocking dispatch as an empty reply. That is an unknown
                    // outcome, not evidence that Apply did not commit.
                    Err(crate::actors::client::ClientError::Unreachable) => {
                        outcome_ambiguous = true;
                    }
                    Err(error) if !outcome_ambiguous => return Err(error),
                    // Once a prior attempt may have committed, a replacement
                    // leader's verifier/barrier failure cannot resolve it.
                    Err(_) => {}
                }
            }
        }

        match local_redrive(ingress) {
            AttestedRedriveAttempt::NotSent => {}
            AttestedRedriveAttempt::Ambiguous => outcome_ambiguous = true,
            AttestedRedriveAttempt::Reply(envelope) => {
                if let Some(next) = decode_service_raft_redirect(&envelope) {
                    redirect = next;
                    backoff();
                    continue;
                }
                match decode_host_invoke_envelope(&envelope) {
                    Ok(reply) => return Ok(reply),
                    Err(crate::actors::client::ClientError::Unreachable) => {
                        outcome_ambiguous = true;
                    }
                    Err(error) if !outcome_ambiguous => return Err(error),
                    Err(_) => {}
                }
            }
        }

        backoff();
    }
}

/// The network ingress gate can spend this long consulting the registry to
/// bind a compact voter slot back to its complete authenticated peer identity.
#[cfg(feature = "network")]
const SERVICE_RAFT_VOTER_AUTH_TIMEOUT_MS: u64 = 5_000;

/// Remote transport discovery is deliberately much shorter than an ingress
/// operation. It runs off-router, is coalesced per root, and is retried from
/// durable publication state, so a slow/dead bootstrap never needs to hold a
/// global node thread for the full voter-authentication budget.
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_RESOLUTION_OWNERSHIP_GRACE: Duration = Duration::from_millis(250);
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_LEADER_CACHE_TTL: Duration = Duration::from_secs(1);
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_RETRY_BACKOFF: Duration = Duration::from_millis(250);
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES: usize = 16;
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_RAFT_TRANSPORT_MAX_LEADER_HINTS: usize = 4;

/// One end-to-end Raft invocation can consume voter authentication, one
/// all-voter private-sidecar barrier, one read barrier, and up to three
/// proposal waits (fresh-root `Install`, `AdmitIngress`, and `Apply`). Reserve
/// one further proposal window for physical guest execution, transit, and
/// scheduling jitter. The caller applies this once across both the local
/// follower and redirected leader hops rather than restarting a per-hop
/// timeout.
#[cfg(all(feature = "storage", feature = "network"))]
fn service_raft_invoke_timeout(propose_timeout_ms: u64) -> Duration {
    Duration::from_millis(
        SERVICE_RAFT_VOTER_AUTH_TIMEOUT_MS
            .saturating_add(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT_MS)
            .saturating_add(propose_timeout_ms.saturating_mul(5)),
    )
}

impl std::fmt::Display for NodeRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot register VOS service root service: {self:?}")
    }
}

impl std::error::Error for NodeRegistrationError {}

#[cfg(all(feature = "storage", feature = "network"))]
#[derive(Debug)]
pub enum RaftNodeRegistrationError<E> {
    Log(crate::commit::CommitError),
    Open(crate::service::LocalRootTreeOpenError<E>),
    Registration(NodeRegistrationError),
    ReplicationHandlerOccupied([u8; 32]),
    InvalidVoterIdentity(u16),
    CatchUp(crate::service::LocalRootTreeInvokeError),
    ProductionPolicyMismatch,
    Promotion(String),
}

#[cfg(all(feature = "storage", feature = "network"))]
impl<E: core::fmt::Debug> core::fmt::Display for RaftNodeRegistrationError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot register Raft VOS service root tree: {self:?}")
    }
}

#[cfg(all(feature = "storage", feature = "network"))]
impl<E: core::fmt::Debug> core::error::Error for RaftNodeRegistrationError<E> {}

impl AgentResult {
    /// Did the agent finish cleanly (no PVM panics, no host errors)?
    pub fn is_ok(&self) -> bool {
        self.panics == 0 && self.error.is_none()
    }
}

/// Replication / persistence semantics selected per agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consistency {
    /// In-memory only — state is lost when the agent exits. The
    /// default; matches the pre-persistence behaviour.
    #[default]
    Ephemeral,
    /// redb-backed local persistence (no replication, no log).
    Local,
    /// Merkle-CRDT replication: state + DAG + roots are written
    /// atomically on every dispatch, and the observed-effect log
    /// is attached to each DAG node for deterministic replay.
    Crdt,
    /// Raft consensus — every state-changing dispatch appends a
    /// committed log entry. Single-node mode runs as a "self-quorum"
    /// (durable persistence + replay equivalent to `Local` + a log);
    /// cluster machinery (election, AppendEntries,
    /// leader-forwarding `commit_with_log`) activates when peers join.
    Raft,
}

impl Consistency {
    /// Byte encoding, matching the registry `AgentRow.consistency`
    /// wire order (`Ephemeral`=0, `Local`=1, `Crdt`=2, `Raft`=3).
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`Self::as_u8`]; `None` for an unknown byte.
    pub(crate) fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ephemeral),
            1 => Some(Self::Local),
            2 => Some(Self::Crdt),
            3 => Some(Self::Raft),
            _ => None,
        }
    }

    /// Position on the monotone *shareability* lattice — higher means
    /// more widely shared. Confined tiers (`Ephemeral`, `Local`) keep
    /// state on this node; `Crdt`/`Raft` both replicate it off-node and
    /// are rank-equal (distinguished only by algorithm). An installed
    /// agent's shareability may only ever *decrease*: a `Local` keystore
    /// can never be widened into replication. See [`VosNode::seal_consistency`].
    pub(crate) fn shareability(self) -> u8 {
        match self {
            Self::Ephemeral => 0,
            Self::Local => 1,
            Self::Crdt | Self::Raft => 2,
        }
    }

    /// `true` for the node-confined tiers (`Ephemeral`, `Local`) whose
    /// state never leaves this device. Such an agent — the messenger's
    /// MLS keys, CSPRNG seed and decrypted plaintext are the load-bearing
    /// example — must be reachable only from in-process host calls, never
    /// from a remote peer's `InvokeRequest`. The replicated tiers
    /// (`Crdt`/`Raft`) are the only ones that legitimately answer the
    /// network. See [`NodeService::dispatch_invoke`].
    pub(crate) fn is_node_confined(self) -> bool {
        self.shareability() < Self::Crdt.shareability()
    }
}

/// The effective consistency once the monotone locality seal is applied: a
/// persisted `sealed` floor pins the tier this instance was first spawned at,
/// so a forged or merged registry row can't change it. Honoured: an exact
/// re-spawn, or a deliberate *narrowing* (lower shareability — more confined).
/// Pinned back to `sealed`: a shareability *widening* (e.g. `Local`→`Crdt`),
/// AND a `Crdt`↔`Raft` *lateral* — same shareability, but it swaps the
/// replication trust model (consensus-sequenced Raft ↔ merge-anyone CRDT), so
/// a forged catalog byte must not be able to downgrade a Raft replica to CRDT.
#[cfg(feature = "storage")]
pub(crate) fn effective_after_seal(
    sealed: Option<Consistency>,
    requested: Consistency,
) -> Consistency {
    match sealed {
        Some(s) if requested == s => requested,
        Some(s) if requested.shareability() < s.shareability() => requested,
        Some(s) => s,
        None => requested,
    }
}

/// Configuration for registering an agent in the node.
/// Content-addressed pure Task made available to one actor runtime. The blob
/// is already transpiled; the witness window comes from the Task ELF's
/// `__VOS_WITNESS` symbol. Signed package carriage is layered above this
/// host-neutral registration shape.
pub struct TaskBlobConfig {
    pub blob: Vec<u8>,
    pub witness_addr: u32,
    pub witness_capacity: u32,
}

pub struct AgentConfig {
    /// PVM blob (already transpiled).
    pub blob: Vec<u8>,
    /// Installed instance name, recorded in the node's [`AgentNames`]
    /// reverse map at register time so the auth path can resolve this
    /// agent's `ServiceId` back to a name (actor-local grant probes,
    /// `intra_caps` targets). `None` for anonymous/test agents — the
    /// reverse map simply gets no row, and name-keyed auth lookups fall
    /// back to deny (the prior behaviour for every non-registry target).
    pub name: Option<String>,
    /// Initial payloads to deliver on startup.
    pub init_payloads: Vec<Vec<u8>>,
    /// Pre-populated storage entries (key, value).
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
    /// Pure Task dependencies callable by content hash from this actor.
    pub task_blobs: Vec<TaskBlobConfig>,
    /// Optional data directory for state persistence. When set and
    /// `consistency` isn't `Ephemeral`, the agent's redb file is
    /// created at `{data_dir}/agents/{svc_id}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Replication / persistence semantics for this agent.
    pub consistency: Consistency,
    /// Opt a node-confined (`Local`/`Ephemeral`) agent OUT of the
    /// device-private network gate, so remote peers may invoke it. The
    /// gate exists for agents whose single-node state is device-private
    /// (the messenger's MLS keys, CSPRNG seed, decrypted plaintext) and
    /// must never leave the device — those stay confined (the default,
    /// `false`). But a single-node agent can also be authoritative state
    /// deliberately served over the network — a per-node authoritative store
    /// answering remote reads, a stateless forwarding bridge — and those set
    /// this so the confinement gate lets peer invokes through. No effect on
    /// `Crdt`/`Raft` agents (never confined) — see
    /// [`Consistency::is_node_confined`] and [`NodeService::dispatch_invoke`].
    pub network_reachable: bool,
    /// 32-byte handle that identifies the *replication group* this
    /// agent belongs to. Replicas of the same logical actor on
    /// different nodes share this id and use it to find each other
    /// over the network. Only meaningful when `consistency ==
    /// Crdt`. `None` means "this CRDT actor has no peers" — its
    /// DAG stays purely local.
    pub replication_id: Option<[u8; 32]>,
    /// Pre-opened, shared `redb::Database` for the agent's
    /// `CrdtCommit`. When `register` plans to wire this actor
    /// into the network's `SyncHandler`, it opens the file
    /// here, hands the same `Arc` to the agent's commit
    /// strategy *and* to the sync layer — redb is exclusive on
    /// file open, so this is the only way to share. `None`
    /// means the agent thread opens the file itself.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_db: Option<Arc<redb::Database>>,
    /// Companion to `pre_opened_db`: the commit lock that
    /// serializes the agent thread's `commit_with_log` against
    /// the sync ticker's `insert_node` + `compact_roots`. Both
    /// must hand it to their `CrdtCommit::from_db_arc_locked`
    /// for the serialization to actually happen.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_lock: Option<Arc<Mutex<()>>>,
    /// Static cluster membership (list of `node_prefix`es) for
    /// `Consistency::Raft`. Empty = single-node degenerate mode.
    /// All cluster members must list the same set in the same
    /// order.
    pub members: Vec<u16>,
    /// Periodic `tick()` interval in milliseconds. When `Some(>0)`, the
    /// agent thread dispatches a synthetic `tick` message to the actor's
    /// `tick` handler about every interval, *between* inbound work — the
    /// same heartbeat the `.so` extension gets via its `tick_ms`. `None`
    /// (default) → no ticking. Only set this on agents that define a
    /// `tick` handler. Best-effort cadence: a long invoke delays the next
    /// tick (the thread never preempts a handler).
    pub tick_ms: Option<u64>,
    /// Declared intra-system capabilities — the ceiling [`SpaceRole`] this
    /// agent may exercise at each named target on outbound invokes. A matching
    /// cap authenticates autonomous calls as this [`ServiceId`]; external
    /// callers remain bounded by the lower of their role and the cap. Empty
    /// denies role-bearing relays. See [`IntraCap`].
    pub intra_caps: Vec<crate::actors::IntraCap>,
    /// Pre-spawned Raft worker for `Consistency::Raft` multi-mode
    /// replication. `register` spawns this when the right
    /// conditions hold (multi-member + network attached + storage
    /// feature on) and hands it to the agent thread, which builds
    /// `RaftCommit::from_worker` with it. Caller code shouldn't
    /// set this directly.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_worker: Option<crate::raft::RaftWorker>,
    /// Apply-receiver paired with `raft_worker`. Drained by
    /// `RaftCommit::commit_with_log` while waiting for an
    /// in-flight propose to commit.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_apply_rx: Option<std::sync::mpsc::Receiver<u64>>,
    /// Per-replica gate on peer-merged CRDT nodes (see
    /// [`NodeValidator`](crate::commit::NodeValidator)). Installed on the
    /// space-registry replica to bind the genesis `set_root` to the
    /// advertised space_id; `None` (default) accepts all peer nodes.
    #[cfg(feature = "storage")]
    pub node_validator: Option<crate::commit::NodeValidator>,
}

impl AgentConfig {
    /// Build a config with no persistence (the default).
    pub fn new(blob: Vec<u8>) -> Self {
        Self {
            blob,
            name: None,
            init_payloads: Vec::new(),
            storage: Vec::new(),
            task_blobs: Vec::new(),
            data_dir: None,
            consistency: Consistency::Ephemeral,
            network_reachable: false,
            replication_id: None,
            #[cfg(feature = "storage")]
            pre_opened_db: None,
            #[cfg(feature = "storage")]
            pre_opened_lock: None,
            members: Vec::new(),
            tick_ms: None,
            intra_caps: Vec::new(),
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_worker: None,
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_apply_rx: None,
            #[cfg(feature = "storage")]
            node_validator: None,
        }
    }

    /// Set the static cluster membership for `Consistency::Raft`
    /// — list of `node_prefix`es. Same list on every replica.
    pub fn with_members(mut self, members: Vec<u16>) -> Self {
        self.members = members;
        self
    }

    /// Dispatch a synthetic `tick` to this agent's `tick` handler about
    /// every `ms` milliseconds (0 disables). Only meaningful for agents
    /// that define a `tick` handler.
    pub fn with_tick_ms(mut self, ms: u64) -> Self {
        self.tick_ms = (ms > 0).then_some(ms);
        self
    }

    /// Set the bounded authority this agent may exercise on outbound invokes.
    /// Matching autonomous calls carry this agent's identity; this is the
    /// explicit host grant required by protected native extensions.
    pub fn with_intra_caps(mut self, caps: Vec<crate::actors::IntraCap>) -> Self {
        self.intra_caps = caps;
        self
    }

    /// Attach initial payloads dispatched on cold start.
    pub fn with_init_payloads(mut self, payloads: Vec<Vec<u8>>) -> Self {
        self.init_payloads = payloads;
        self
    }

    /// Record the agent's installed instance name so the node's
    /// [`AgentNames`] reverse map can resolve its `ServiceId` back to a
    /// name for the auth path. Set by `vosx` from the manifest/registry
    /// at install time; left unset for anonymous test agents.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Attach pre-populated storage (key, value) entries.
    pub fn with_storage(mut self, storage: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        self.storage = storage;
        self
    }

    /// Install a content-addressed pure Task into this actor's runtime.
    /// Returns configuration only; callers derive the hash with
    /// [`crate::provable::task_blob_hash`] when configuring the parent.
    pub fn with_task_blob(
        mut self,
        blob: Vec<u8>,
        witness_addr: u32,
        witness_capacity: u32,
    ) -> Self {
        self.task_blobs.push(TaskBlobConfig {
            blob,
            witness_addr,
            witness_capacity,
        });
        self
    }

    /// Pick the replication/persistence strategy.
    pub fn with_consistency(mut self, c: Consistency) -> Self {
        self.consistency = c;
        self
    }

    /// Let remote peers invoke this node-confined (`Local`/`Ephemeral`)
    /// agent — for single-node state that is authoritative-but-network-
    /// served (a per-node authoritative store, a forwarding bridge) rather
    /// than device-private. Leaves device-private agents (the messenger)
    /// confined by default. See [`AgentConfig::network_reachable`].
    pub fn network_reachable(mut self) -> Self {
        self.network_reachable = true;
        self
    }

    /// Enable persistence under the given data directory.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Pin this agent into a named replication group. Replicas
    /// across nodes that share the same id automatically discover
    /// each other (over an attached `Network`) and converge their
    /// merkle-DAGs.
    pub fn with_replication_id(mut self, id: [u8; 32]) -> Self {
        self.replication_id = Some(id);
        self
    }

    /// Gate peer-merged CRDT nodes through `validator` (see
    /// [`NodeValidator`](crate::commit::NodeValidator)). The daemon sets
    /// this on the space-registry replica to reject a forged genesis
    /// whose CID doesn't derive the advertised space_id.
    #[cfg(feature = "storage")]
    pub fn with_node_validator(mut self, validator: crate::commit::NodeValidator) -> Self {
        self.node_validator = Some(validator);
        self
    }

    /// Convenience: derive a replication id from the agent's blob
    /// plus a logical name. Replicas with identical (blob, name)
    /// automatically share an id without manifest coordination.
    pub fn auto_replication_id(mut self, name: &str) -> Self {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(name.as_bytes());
        h.update(&[0u8]); // delimiter so name||blob ≠ shifted variants
        h.update(&self.blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        self.replication_id = Some(out);
        self
    }

    /// Derive the redb path for this agent from its data directory
    /// and service ID. Only meaningful when the `storage` feature
    /// is enabled.
    #[cfg(feature = "storage")]
    fn db_path(&self, id: ServiceId) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let dir = data_dir.join("agents");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{:08x}.redb", id.0)))
    }

    /// Node-local sidecar recording the narrowest consistency tier this
    /// instance was ever spawned at — the monotone locality seal. Sits
    /// next to the agent's redb so it shares the agent's lifetime.
    #[cfg(feature = "storage")]
    fn seal_path(&self, id: ServiceId) -> Option<std::path::PathBuf> {
        let dir = self.data_dir.as_ref()?.join("agents");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{:08x}.seal", id.0)))
    }

    /// Enforce the monotone locality seal on this config's requested
    /// consistency. Best-effort and node-local: with no `data_dir` or no
    /// `name` there is nothing durable to seal, so the request passes
    /// through. Otherwise the (possibly narrowed) tier is persisted, so a
    /// later spawn — even one driven by a forged or CRDT-merged registry
    /// row — can never *widen* a sealed agent's shareability. This is the
    /// load-bearing half of immutable-local: the registry is replicated
    /// and not trusted, so the seal lives here on the host, ahead of the
    /// sync-attach branches that key on `config.consistency`.
    #[cfg(feature = "storage")]
    fn apply_consistency_seal(&mut self, id: ServiceId) {
        if self.name.is_none() {
            return;
        }
        let Some(path) = self.seal_path(id) else {
            return;
        };
        let sealed = std::fs::read(&path)
            .ok()
            .and_then(|b| b.first().copied())
            .and_then(Consistency::from_u8);
        let effective = effective_after_seal(sealed, self.consistency);
        if effective != self.consistency {
            warn!(
                %id,
                requested = ?self.consistency,
                sealed = ?sealed,
                effective = ?effective,
                "consistency: refusing to widen a sealed agent; pinning to the sealed tier",
            );
        }
        let _ = std::fs::write(&path, [effective.as_u8()]);
        self.consistency = effective;
    }
}

/// Configuration for registering a native extension in the node.
pub struct ExtensionConfig {
    /// Path to the extension `.so` file.
    pub path: std::path::PathBuf,
    /// Installed instance name, recorded in the node's [`AgentNames`]
    /// reverse map at register time. Mirrors [`AgentConfig::name`] for
    /// the extension side — lets an extension be the *target* of a
    /// named `intra_cap` and of actor-local grants. `None` for
    /// anonymous/test extensions.
    pub name: Option<String>,
    /// rkyv-encoded `vos::value::Args` for the extension's constructor.
    /// Empty if the constructor takes no parameters.
    pub init_args: Vec<u8>,
    /// Optional data directory for state persistence.
    /// When set, the extension's redb file is created at
    /// `{data_dir}/extensions/{name}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Declared intra-system capabilities — the ceiling [`SpaceRole`]
    /// this extension may relay to each named target actor. Empty
    /// (the default) means the extension has *no* authority to relay:
    /// every outbound call arrives [`Caller::Unauthenticated`], so
    /// role-gated handlers refuse it. See [`IntraCap`] for the
    /// intersection model and wildcard semantics.
    pub intra_caps: Vec<crate::actors::IntraCap>,
    /// Periodic `tick()` interval, in milliseconds. When
    /// `Some`, the extension driver dispatches a synthetic `tick` message
    /// (routed to the extension's `#[msg] async fn tick(&mut self, ctx)`
    /// handler) roughly every `tick_ms`, between inbound invokes/messages —
    /// how an extension originates periodic work (e.g. a
    /// heartbeat ping) without a self-spun loop. `None` (default) →
    /// no ticking. Best-effort: a long-running invoke legitimately delays
    /// the next tick (the driver never preempts a handler).
    pub tick_ms: Option<u64>,
}

impl ExtensionConfig {
    /// Build a config with no init args and no persistence.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            name: None,
            init_args: Vec::new(),
            data_dir: None,
            intra_caps: Vec::new(),
            tick_ms: None,
        }
    }

    /// Build a config with rkyv-encoded init args.
    pub fn with_args(path: impl Into<std::path::PathBuf>, args: &crate::value::Args) -> Self {
        let bytes = crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(args)
            .expect("rkyv encode Args")
            .to_vec();
        Self {
            path: path.into(),
            name: None,
            init_args: bytes,
            data_dir: None,
            intra_caps: Vec::new(),
            tick_ms: None,
        }
    }

    /// Set the periodic [`tick`](Self::tick_ms) interval in milliseconds.
    /// The extension driver then dispatches a synthetic `tick` message to
    /// the extension's `tick` handler roughly every `ms` between inbound
    /// work. Zero is treated as "no ticking" (same as `None`).
    pub fn with_tick_ms(mut self, ms: u64) -> Self {
        self.tick_ms = (ms > 0).then_some(ms);
        self
    }

    /// Record the extension's installed instance name so the node's
    /// [`AgentNames`] reverse map can resolve its `ServiceId` back to a
    /// name. Set by `vosx` from the manifest; left unset for test
    /// extensions.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Declare the extension's intra-system capabilities — the
    /// ceiling [`SpaceRole`] it may relay to each named target.
    /// An empty list gives the extension no relay authority. See [`IntraCap`].
    pub fn with_intra_caps(mut self, caps: Vec<crate::actors::IntraCap>) -> Self {
        self.intra_caps = caps;
        self
    }

    /// Enable state persistence under the given data directory.
    /// The extension's state is stored under `{data_dir}/extensions`, keyed by
    /// a hash of the installed instance name when present, or by the `.so`
    /// filename for anonymous embedders.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Derive an instance-scoped redb path. Named instances hash the full
    /// operator-controlled name into a traversal-safe filename; anonymous
    /// embedders retain the historical `.so`-stem path.
    #[cfg(feature = "storage")]
    fn db_path(&self) -> std::io::Result<Option<std::path::PathBuf>> {
        let Some(data_dir) = self.data_dir.as_ref() else {
            return Ok(None);
        };
        let name = if let Some(instance_name) = self.name.as_deref() {
            use std::fmt::Write as _;

            let digest = crate::crypto::blake2b_hash::<16>(
                b"vos/extension/state-file",
                &[instance_name.as_bytes()],
            );
            let mut encoded = String::with_capacity(32);
            for byte in digest {
                let _ = write!(encoded, "{byte:02x}");
            }
            format!("instance-{encoded}")
        } else {
            self.path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("extension")
                .trim_start_matches("lib")
                .to_owned()
        };
        let dir = data_dir.join("extensions");
        std::fs::create_dir_all(&dir)?;
        Ok(Some(dir.join(format!("{name}.redb"))))
    }
}

/// Synchronous invoke request routed through `invoke_routes`.
///
/// `chain` carries the ServiceIds of the agents already on the
/// stack of synchronous invokes leading to this hop, including the
/// caller. Each agent's `external_invoke` checks the chain before
/// forwarding so an A→B→A cycle aborts immediately at the second
/// hop instead of deadlocking until the 10 s reply timeout. The
/// chain doubles as a depth counter — capped at
/// [`MAX_CROSS_AGENT_DEPTH`] hops.
const NATIVE_CALL_QUEUED: u8 = 0;
const NATIVE_CALL_RUNNING: u8 = 1;
const NATIVE_CALL_CANCELED: u8 = 2;

/// Shared ownership handshake for a service actor's synchronous native call.
///
/// A caller may abandon only work that is still queued. Once the extension
/// worker atomically claims the request, the caller waits for its real durable
/// outcome even if the ordinary ask deadline passes. This prevents a timeout
/// from being reported while the serial worker later performs the call.
#[derive(Clone)]
struct NativeCallControl {
    deadline: Instant,
    state: Arc<AtomicU8>,
}

impl NativeCallControl {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            state: Arc::new(AtomicU8::new(NATIVE_CALL_QUEUED)),
        }
    }

    /// Claim queued work for execution, unless its caller canceled it or its
    /// deadline already elapsed. Exactly one of this and `cancel_queued` wins.
    fn try_start(&self) -> bool {
        if Instant::now() >= self.deadline {
            let _ = self.cancel_queued();
            return false;
        }
        self.state
            .compare_exchange(
                NATIVE_CALL_QUEUED,
                NATIVE_CALL_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_queued(&self) -> bool {
        self.state
            .compare_exchange(
                NATIVE_CALL_QUEUED,
                NATIVE_CALL_CANCELED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

struct InvokeRequest {
    /// Who's calling — host-side identity as seen by the dispatch
    /// gate. `Caller::Peer` for libp2p inbound (multihash bytes of
    /// the noise-verified PeerId); `Caller::Actor` for intra-system
    /// invokes (the calling actor's ServiceId); `Caller::Unauthenticated`
    /// for host-initiated calls and built-in ingress routes.
    #[allow(dead_code)] // Consumed by macro-emitted dispatch.
    caller: crate::actors::Caller,
    /// Space-wide role byte for `caller`, decoded as a
    /// [`SpaceRole`](crate::actors::SpaceRole) discriminant.
    /// `None` for callers without a space-level grant (Unauthenticated
    /// or unknown peers). Populated by [`NodeService::dispatch_invoke`]
    /// when the host resolves an actor-local grant.
    #[allow(dead_code)] // Consumed by authenticated dispatch.
    space_role: Option<u8>,
    /// Actor-local role byte for `caller`, decoded against the
    /// target actor's [`Role`](crate::Actor::Role) discriminant.
    /// `None` when no actor-local grant exists; falls back to the
    /// space-level grant mapped via `SPACE_ROLE_MAP`. Populated
    /// when the host resolves a space grant.
    #[allow(dead_code)] // Consumed by authenticated dispatch.
    actor_local_role: Option<u8>,
    /// Consensus-significant origin observed by another replica before it
    /// redirected this Raft invocation. Only the network ingress may populate
    /// this field, after authenticating the forwarding peer as a current voter.
    #[cfg(all(feature = "network", feature = "storage"))]
    delegated_origin: Option<crate::service::Origin>,
    /// Host-private marker for the canonical authority decision protocol.
    /// Ordinary actor calls cannot set it; a cross-node hop carries it only
    /// inside voter-authenticated Raft delegation.
    role_authority_request: bool,
    /// Host-private marker for a root upgrade authenticated as an Admin by
    /// the serving daemon. Raft redirects preserve it only inside the
    /// full-PeerId voter-authenticated delegation wire.
    root_upgrade_request: bool,
    /// Stable caller-selected identity for a native-extension dispatch. Only
    /// the service Refine bridge populates it; ordinary routes allocate their
    /// existing host dispatch identity.
    invocation_id: Option<crate::service::InvocationId>,
    /// Present only for the service-actor native-extension bridge. Ordinary
    /// invoke routes retain their existing timeout semantics.
    native_call: Option<NativeCallControl>,
    msg: Vec<u8>,
    reply: ReplyChannel,
    // Read by agent_thread via `&req.chain` before moving `req`
    // into handle_invoke_request; rustc's read analysis misses
    // that pattern when the rest of the struct is then consumed.
    #[allow(dead_code)]
    chain: Vec<u32>,
}

/// The reply sink of an [`InvokeRequest`]. `Sync` (std mpsc) is the default for
/// every caller (actor/service/registry/libp2p replies) — its receiver is
/// awaited with a blocking `recv_timeout`. `Async` (a `futures_channel::oneshot`) lets a
/// Transport-mode connection task await its reply *on the
/// cooperative executor* — no blocking-pool thread, correlated per-call — so
/// many concurrent connections keep serving while one waits for its `ctx.ask`.
enum ReplyChannel {
    Sync(mpsc::Sender<Vec<u8>>),
    Async(futures_channel::oneshot::Sender<Vec<u8>>),
}

impl ReplyChannel {
    /// Deliver `reply` to the waiting caller. Single-use for `Async` (a
    /// `oneshot` consumes its sender). A closed/canceled receiver — the caller
    /// already timed out or gave up — is ignored, never panics.
    fn send(self, reply: Vec<u8>) -> bool {
        match self {
            ReplyChannel::Sync(tx) => tx.send(reply).is_ok(),
            ReplyChannel::Async(tx) => tx.send(reply).is_ok(),
        }
    }
}

/// Maximum number of cross-agent invoke hops in one synchronous
/// chain. Each agent's external_invoke aborts forwarding when
/// `chain.len()` reaches this. Picked generously — typical chains
/// are 1–3 deep; 32 catches runaway recursion without limiting
/// realistic compositions.
const MAX_CROSS_AGENT_DEPTH: usize = 32;

/// Maximum size, in bytes, of a single reply sent through an
/// `InvokeRequest`'s `reply_tx`. Distinct from the per-call
/// recording cap (`DEFAULT_REPLY_CAP`, 16 KiB) which bounds DAG
/// log size. The producer cap is much larger — it's a guardrail
/// against runaway memory pressure when an agent or worker
/// produces a multi-megabyte reply, not a consensus-history
/// concern. Replies exceeding this are dropped at the producer
/// side and surface as `InvokeError::NotFound` at the caller.
///
/// 8 MiB accommodates STARK proof bodies (the prover extension's
/// `prove` returns ~1.4 MiB; future production-config
/// proofs may exceed 2 MiB) without admitting unboundedly large
/// replies.
const MAX_PRODUCER_REPLY: usize = 8 * 1024 * 1024;

/// Send `reply` through `reply_tx` if it's within the producer
/// cap; otherwise log and drop the channel so the caller gets a
/// disconnect-shaped failure. Pulled out to share between
/// `handle_invoke_request` and `extension_thread`.
fn send_reply_capped(reply: ReplyChannel, bytes: Vec<u8>, svc_id: ServiceId) -> bool {
    if bytes.len() > MAX_PRODUCER_REPLY {
        warn!(
            %svc_id,
            size = bytes.len(),
            cap = MAX_PRODUCER_REPLY,
            "reply exceeds producer-side cap; dropping channel",
        );
        drop(reply); // disconnect (Sync) / cancel (Async) → caller sees failure
        false
    } else {
        reply.send(bytes)
    }
}

/// Result of the pre-forward safety check on a synchronous invoke.
#[derive(Debug, PartialEq, Eq)]
enum InvokeForwardCheck {
    Allowed,
    /// Target is already in the chain — forwarding would form a
    /// cycle (and deadlock until the 10 s reply timeout).
    Cycle,
    /// Chain has reached the depth cap.
    DepthExceeded,
}

/// Node-owned signer used only for exact clean authority requests originating
/// at the SSH transport boundary. Keeping the callback behind this typed
/// wrapper prevents an ingress adapter from turning the daemon identity into a
/// general-purpose signing oracle.
#[cfg(feature = "ssh-ingress")]
#[derive(Clone)]
struct IngressNodeAttester {
    node: crate::agent::sdk::NodeId,
    signer: Arc<dyn Fn(&[u8]) -> Option<[u8; 64]> + Send + Sync>,
}

/// Decide whether to forward an invoke to `target` given the
/// caller's current chain. Pulled out as a free function so the
/// rule is testable without spinning up agent threads.
fn check_invoke_forward(chain: &[u32], target: u32) -> InvokeForwardCheck {
    if chain.contains(&target) {
        InvokeForwardCheck::Cycle
    } else if chain.len() >= MAX_CROSS_AGENT_DEPTH {
        InvokeForwardCheck::DepthExceeded
    } else {
        InvokeForwardCheck::Allowed
    }
}

/// A multi-agent VOS node.
///
/// Each agent runs on its own thread with its own `VosRuntime`.
/// All services share a global ID namespace scoped by `node_prefix`.
pub struct VosNode {
    node_prefix: u16,
    next_local: AtomicU16,
    /// Map from ServiceId → agent channel. Multiple services can map
    /// to the same agent (an agent with child actors).
    routes: HashMap<u32, mpsc::Sender<Envelope>>,
    agents: Vec<AgentHandle>,
    /// Outbound channel — agent threads send cross-service transfers here.
    outbox_tx: mpsc::Sender<Envelope>,
    outbox_rx: mpsc::Receiver<Envelope>,
    /// Map from ServiceId → synchronous invoke channel. Both
    /// workers and PVM agents register here. Wrapped in an
    /// `Arc<Mutex<...>>` so threads spawned earlier can resolve
    /// peers registered later — the alternative (cloning the map
    /// at thread spawn time) freezes A's view of the world before
    /// B exists, breaking cross-agent invoke order-independent.
    invoke_routes: InvokeRoutes,
    /// Canonical service actor identity to local host route. Unlike `ServiceId`,
    /// this identity is preserved end-to-end in WorkEnvelope and never
    /// truncated into the 32-bit control-plane namespace.
    service_actor_routes: Arc<RwLock<HashMap<crate::service::ActorId, ActorRoute>>>,
    /// Per-process entropy and monotone ordinal for host-originated service work.
    /// The seed prevents fallback invocation identities repeating after a
    /// process restart.
    service_invocation_seed: [u8; 32],
    service_invocation_ordinal: Arc<AtomicU64>,
    /// Trusted local admission clock for service work. External ingress never
    /// carries this value; the root-service thread stamps it immediately
    /// before scheduling. It is seeded from wall time so a process restart
    /// cannot reset durable deadline comparisons to one.
    service_logical_timeslot: Arc<AtomicU64>,
    /// Reverse map `local_id → instance name`, populated at register
    /// time and read live by the auth path (the libp2p gate's
    /// actor-local probe and extension relays). Shared (cheap clone)
    /// into [`NodeService`] and into each service-extension thread.
    /// See [`AgentNames`].
    agent_names: AgentNames,
    /// Set by [`VosNode::run_until_idle`] (or `collect`) when the
    /// node decides it's done. Threads poll this at the top of
    /// their main loop and exit cleanly. Replaces the per-agent
    /// "exit after N seconds idle" heuristic with explicit
    /// node-driven lifecycle.
    ///
    /// NOTE: agent threads do NOT poll this directly — they each poll their
    /// own [`Self::agent_shutdown`] flag (which a node-wide shutdown fans out
    /// to via [`Self::signal_node_shutdown`]). This field is still the
    /// node-wide signal for non-agent machinery (network bridge, sync ticker,
    /// `InvokeHandle::is_shutting_down`).
    shutdown: Arc<AtomicBool>,
    /// Per-agent shutdown flags (`local_id → flag`), allocated at
    /// register time. Each agent/extension thread polls ITS OWN flag instead of
    /// the node-wide one, so the daemon can stop a single agent
    /// ([`Self::stop_agent`]) without tearing down the node — the generic
    /// lifecycle primitive shared by every hosted target.
    /// A node-wide shutdown sets every flag here (see
    /// [`Self::signal_node_shutdown`]), so existing teardown is unchanged.
    agent_shutdown: AgentShutdown,
    /// Per-agent descriptive metadata (`id.0 → info`), populated
    /// at register time. Backs the generic `__describe` host primitive
    /// ([`Self::describe_agent`]) so `vosx <agent> describe` can report an
    /// target's name and running flag uniformly. Keyed on the full
    /// (prefix-scoped) id,
    /// matching [`Self::agent_shutdown`].
    agent_info: AgentInfos,
    /// Last time anything happened on the node — outbox routing,
    /// agent dispatch, worker dispatch, invoke handling. Updated
    /// by both threads and the routing loop. Read by
    /// [`run_until_idle`] to decide when to wind the node down.
    ///
    /// [`run_until_idle`]: VosNode::run_until_idle
    last_activity: ActivityClock,
    /// Optional libp2p network handle. Shared with all agent
    /// threads so cross-node `external_invoke` works regardless of
    /// whether the network was attached before or after agent
    /// registration. `None` inside the `Mutex` until
    /// [`attach_network`](Self::attach_network) runs.
    #[cfg(feature = "network")]
    pub(crate) shared_network: SharedNetwork,
    /// This daemon's operator: the PeerId bytes of the CLI identity that
    /// ran `vosx space up` (loaded in-process from the operator's
    /// `vosx/identity.key`). A node-confined agent — the messenger holds
    /// device-private MLS keys, the CSPRNG seed and decrypted plaintext —
    /// is reachable over the network ONLY by this exact caller (see
    /// [`NodeService::dispatch_invoke`]): the operator drives their own
    /// messenger with `vosx messenger …`, which dials the daemon as a
    /// libp2p call from THIS identity, while every other peer — including a
    /// remote admin of the same space — is refused. `None` (the default:
    /// a raw `vosx run`, a transient peer, or a test node) fails closed, so
    /// no peer reaches a confined agent. Set by
    /// [`set_operator_peer`](Self::set_operator_peer) before
    /// [`attach_network`](Self::attach_network).
    #[cfg(feature = "network")]
    operator_peer: Option<Vec<u8>>,
    /// Signs root-host attestations after the canonical role authority has
    /// durably accepted an invite. Catalog mutations are signed directly by
    /// their author and this callback is never shared with an agent thread.
    /// `None` makes host attestation fail closed. Set by
    /// [`set_operator_signer`](Self::set_operator_signer).
    operator_signer: Option<crate::registry::OperatorSigner>,
    /// Map: replication group → local replica handle.
    /// Populated by `register` whenever a CRDT actor with a
    /// `replication_id` is added. Read by [`NodeService`] (db
    /// only) to answer inbound sync queries; the agent thread
    /// and sync ticker share the `commit_lock` to serialize
    /// their writes against each other.
    #[cfg(all(feature = "network", feature = "storage"))]
    pub(crate) crdt_replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    /// Map: ServiceId word → replication group, for agents running
    /// the multi-mode Raft worker. Shared into every extension
    /// thread (via [`RaftFwd`]) so the ask path can recognize a
    /// follower-rejected write and re-address it to the group's
    /// current leader.
    #[cfg(all(feature = "network", feature = "storage"))]
    raft_hosts: RaftHosts,
    /// Exact Raft group → root-owned private-ingress sidecar sink.
    #[cfg(all(feature = "network", feature = "storage"))]
    service_private_ingress_routes: PrivateIngressRoutes,
    /// Short-lived leader cache plus one in-flight marker per Raft root.
    /// Resolution workers never run on the global envelope router, and
    /// repeated 250 ms durable redrives coalesce behind the same marker.
    #[cfg(all(feature = "network", feature = "storage"))]
    service_raft_transport_resolutions: RaftTransportResolutions,
    /// Monotone token used only to distinguish ownership of overlapping
    /// resolver workers. Candidate progress is stored per destination in the
    /// resolution entry and never depends on this node-global value.
    #[cfg(all(feature = "network", feature = "storage"))]
    service_raft_transport_ownership_generation: AtomicU64,
    /// Prepared Raft roots remain absent from public route tables while voter
    /// promotion is pending. Background workers send a type-erased publication
    /// closure here once final non-joint membership is locally visible.
    #[cfg(all(feature = "network", feature = "storage"))]
    pending_service_root_ready_tx: mpsc::Sender<PendingRootReady>,
    #[cfg(all(feature = "network", feature = "storage"))]
    pending_service_root_ready_rx: mpsc::Receiver<PendingRootReady>,
    #[cfg(all(feature = "network", feature = "storage"))]
    pending_service_root_threads: Vec<thread::JoinHandle<()>>,
    #[cfg(all(feature = "network", feature = "storage"))]
    pending_service_root_ids: Arc<Mutex<std::collections::HashSet<u32>>>,
    #[cfg(all(feature = "network", feature = "storage"))]
    pending_service_root_actors: Arc<Mutex<std::collections::HashSet<crate::service::ActorId>>>,
    /// Optional manifest payload exposed to peers via
    /// [`Frame::ManifestReq`](crate::network::Frame::ManifestReq).
    /// Populated by [`set_manifest`](Self::set_manifest) before
    /// [`attach_network`](Self::attach_network) — vosx loads the
    /// space.toml + actor blobs and stashes them here so the
    /// `NetworkService` impl can serve them when a `vosx join`er
    /// asks. Set-once; `None` for nodes that don't expose a
    /// manifest (transient peers, manifest-less raw `vosx run`).
    #[cfg(feature = "network")]
    pub(crate) manifest: Arc<OnceLock<crate::network::ManifestReply>>,
    /// Join handles for the per-replica sync threads spawned
    /// by [`spawn_sync_thread`]. We keep these so [`collect`]
    /// can wait for the threads to exit before returning —
    /// otherwise the threads outlive the node, hold open
    /// `Arc<redb::Database>` references, and the next
    /// `redb::Database::create` against the same file fails
    /// with `Database already open. Cannot acquire lock`.
    #[cfg(all(feature = "network", feature = "storage"))]
    sync_threads: Vec<thread::JoinHandle<()>>,
    /// Built-in ingress listeners are host infrastructure, not actors. Their
    /// threads share the node shutdown signal and are joined before routes are
    /// torn down.
    #[cfg(any(feature = "http-ingress", feature = "ssh-ingress"))]
    ingress_threads: Vec<thread::JoinHandle<()>>,
    /// Exact daemon identity used to attest SSH-authenticated authority
    /// requests. The signer is never exposed directly and is configured once
    /// before an ingress listener receives traffic.
    #[cfg(feature = "ssh-ingress")]
    ingress_node_attester: Option<IngressNodeAttester>,
    /// Content-addressed store for large opaque blobs (today: STARK
    /// proof bodies; future: any payload too big to ride inline
    /// through the PVM dispatch envelope). Keyed by domain-tagged
    /// blake2b-256 of the bytes — see [`Self::put_proof_blob`].
    ///
    /// Always-on in-memory hot cache. When
    /// [`proof_blobs_dir`](Self::proof_blobs_dir) is set, every
    /// `put` writes through to disk and every on-miss `get` lazy-
    /// loads from disk, so restarts don't lose cached proofs.
    pub(crate) proof_blobs: ProofBlobStore,
    /// Optional persistent backing for the proof-blob CAS. When
    /// `Some`, blobs land at `{dir}/{hex_hash}` on `put`, and a
    /// hot-cache miss falls back to a read from that path before
    /// returning `None`. `None` keeps the store pure in-memory —
    /// matches the in-memory mode and is what tests use unless
    /// they explicitly opt in.
    pub(crate) proof_blobs_dir: Option<std::path::PathBuf>,
    /// Directory the node serves *program* blobs (actor ELFs) from over
    /// [`Frame::FetchProgramBlob`](crate::network::Frame::FetchProgramBlob),
    /// content-addressed as `{dir}/{hex_hash}`. Set by the host (vosx points
    /// it at its `blob_store` cache) so `vos` stays cache-agnostic — it only
    /// reads files by hash, never owns the cache. `None` serves nothing.
    pub(crate) program_blobs_dir: Option<std::path::PathBuf>,
    /// Agent-native Local image owner. This is deliberately not represented
    /// in `routes` or `invoke_routes`: those tables use the transitional
    /// compact ServiceId namespace, while Agent-native control is addressed
    /// exclusively by full AgentId / ActorId values and signed receipts.
    local_agent_host: Option<crate::agent::host::AgentHostControl>,
    /// Sole clean-generation production supervisor owner. It becomes visible
    /// to ingress only after its initial authenticated reconciliation and is
    /// stopped and joined with the node.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_agent_owner: Option<crate::agent::production_worker::AgentProductionWorker>,
    /// Live read-only ingress exposure. Route mutation and lifecycle ownership
    /// stay in `clean_agent_owner`; shutdown clears this slot before joining.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_agent_ingress_supervisor:
        Arc<RwLock<Option<crate::agent::production_owner::CleanAgentIngress>>>,
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_agent_recovering: Arc<AtomicBool>,
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_local_lifecycle_queue: Arc<crate::agent::local_lifecycle::LocalLifecycleQueue>,
}

/// Shared content-addressed proof-blob store. Cheap to clone; both
/// the node's `Self` and any extension threads that need to look up
/// blobs receive an `Arc` to the same `RwLock<HashMap<...>>`.
pub(crate) type ProofBlobStore = Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>;

/// Content address for a proof blob. Domain-tagged blake2b-256 so
/// the namespace can't collide with other hash uses on the node
/// (replication IDs, CRDT CIDs, etc.).
pub fn proof_blob_hash(bytes: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(b"vos/proof-blob", &[bytes])
}

/// Lower-case hex encoding of a proof-blob hash. Used as the
/// filename under [`VosNode::proof_blobs_dir`].
fn proof_blob_filename(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        use core::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Shared handle for one CRDT replication group. The same
/// `Arc<Database>` powers the agent's `CrdtCommit` and the
/// sync layer's `SyncHandler`; the `commit_lock` serializes
/// the agent's `commit_with_log` against the sync ticker's
/// `insert_node` + `compact_roots`.
#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Clone)]
pub(crate) struct ReplicaSlot {
    pub db: Arc<redb::Database>,
    pub commit_lock: Arc<Mutex<()>>,
    /// Installed instance name of the replica, used by the sync-serve
    /// path to membership-gate private (`msg-*`) groups. Empty for
    /// anonymous/test replicas — those serve openly (ungated).
    pub name: String,
    /// Per-replica gate applied to peer-merged nodes on the SYNC INGEST
    /// path (`sync_with_peer` → `insert_node`) — this is where peer
    /// nodes actually enter the DAG, so the registry's genesis validator
    /// must live here, not just on the agent thread's strategy. `None`
    /// accepts all peer nodes.
    pub node_validator: Option<crate::commit::NodeValidator>,
}

/// Shared invoke-route table. Cheap to clone and pass to threads.
type InvokeRoutes = Arc<Mutex<HashMap<u32, mpsc::Sender<InvokeRequest>>>>;

/// Host-private sidecar request routed directly to one Raft root thread. It
/// never shares the actor invocation channel or a guest-visible wire.
#[cfg(all(feature = "network", feature = "storage"))]
struct PrivateIngressUpload {
    invocation: crate::service::InvocationId,
    reference: crate::service::BlobRef,
    bytes: Vec<u8>,
    deadline: Instant,
    state: Arc<Mutex<PrivateIngressUploadState>>,
    reply: mpsc::Sender<bool>,
}

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateIngressUploadState {
    Queued,
    Persisting,
    Cancelled,
}

#[cfg(all(feature = "network", feature = "storage"))]
struct PrivateIngressRoute {
    tx: mpsc::SyncSender<PrivateIngressUpload>,
    quiescence_tx: mpsc::SyncSender<mpsc::Sender<bool>>,
    barrier: PrivateIngressBarrier,
    /// Expected replay-verification policy for this exact application group.
    /// Membership admission compares it with the authenticated join request
    /// before calling `change_membership`.
    production_trust_policy: Option<[u8; 32]>,
}

#[cfg(all(feature = "network", feature = "storage"))]
struct PrivateIngressBarrier(AtomicBool);

#[cfg(all(feature = "network", feature = "storage"))]
impl PrivateIngressBarrier {
    fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    fn try_acquire(&self) -> Option<PrivateIngressBarrierGuard<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| PrivateIngressBarrierGuard(&self.0))
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
struct PrivateIngressBarrierGuard<'a>(&'a AtomicBool);

#[cfg(all(feature = "network", feature = "storage"))]
impl Drop for PrivateIngressBarrierGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
type PrivateIngressRoutes = Arc<RwLock<HashMap<[u8; 32], Arc<PrivateIngressRoute>>>>;

#[cfg(all(feature = "network", feature = "storage"))]
fn pending_service_private_ingress_route(
    production_trust_policy: Option<[u8; 32]>,
) -> Arc<PrivateIngressRoute> {
    // Pending registration deliberately drops both receivers. Private-input
    // staging and quiescence therefore fail immediately while the exact Service
    // policy metadata remains visible to join admission.
    let (tx, _receiver) = mpsc::sync_channel(1);
    let (quiescence_tx, _quiescence_receiver) = mpsc::sync_channel(1);
    Arc::new(PrivateIngressRoute {
        tx,
        quiescence_tx,
        barrier: PrivateIngressBarrier::new(),
        production_trust_policy,
    })
}

#[cfg(all(feature = "network", feature = "storage"))]
fn remove_service_private_ingress_route_if(
    routes: &PrivateIngressRoutes,
    replication_id: &[u8; 32],
    expected: &Arc<PrivateIngressRoute>,
) {
    let mut routes = routes.write().unwrap();
    if routes
        .get(replication_id)
        .is_some_and(|route| Arc::ptr_eq(route, expected))
    {
        routes.remove(replication_id);
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
struct PrivateIngressRegistration {
    replication_id: [u8; 32],
    route: Arc<PrivateIngressRoute>,
    receiver: mpsc::Receiver<PrivateIngressUpload>,
    quiescence_receiver: mpsc::Receiver<mpsc::Sender<bool>>,
    routes: PrivateIngressRoutes,
}

#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_PRIVATE_INGRESS_QUEUE_CAPACITY: usize = 16;

#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT_MS: u64 = 5_000;

#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT: Duration =
    Duration::from_millis(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT_MS);

#[cfg(all(feature = "network", feature = "storage"))]
fn stage_service_private_ingress_through_root(
    tx: &mpsc::SyncSender<PrivateIngressUpload>,
    invocation: crate::service::InvocationId,
    reference: crate::service::BlobRef,
    bytes: Vec<u8>,
    timeout: Duration,
) -> bool {
    let state = Arc::new(Mutex::new(PrivateIngressUploadState::Queued));
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx
        .try_send(PrivateIngressUpload {
            invocation,
            reference,
            bytes,
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            state: state.clone(),
            reply: reply_tx,
        })
        .is_err()
    {
        return false;
    }
    match reply_rx.recv_timeout(timeout) {
        Ok(accepted) => accepted,
        Err(mpsc::RecvTimeoutError::Disconnected) => false,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let mut state = state.lock().unwrap();
            match *state {
                PrivateIngressUploadState::Queued => {
                    *state = PrivateIngressUploadState::Cancelled;
                    false
                }
                PrivateIngressUploadState::Cancelled => false,
                PrivateIngressUploadState::Persisting => {
                    // Persistence crossed its non-cancellable durability
                    // boundary before the timeout. Never report a negative
                    // acknowledgement while that write may still commit.
                    drop(state);
                    reply_rx.recv().unwrap_or(false)
                }
            }
        }
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
fn begin_service_private_ingress_upload(upload: &PrivateIngressUpload) -> bool {
    let mut state = upload.state.lock().unwrap();
    if *state != PrivateIngressUploadState::Queued || Instant::now() >= upload.deadline {
        *state = PrivateIngressUploadState::Cancelled;
        return false;
    }
    *state = PrivateIngressUploadState::Persisting;
    true
}

/// Durably stage one private ingress on every voter in the leader's exact
/// steady-state membership before `AdmitIngress` can be proposed. Registry
/// lookups bind compact voter slots to full PeerIds; requests fan out before
/// waiting so one slow voter cannot consume every other voter's budget.
#[cfg(all(feature = "network", feature = "storage"))]
fn stage_service_private_ingress_on_current_voters<B>(
    service: &mut crate::service::LocalRootTreeService<B>,
    request: &crate::service::LocalWorkRequest,
    reference: &crate::service::BlobRef,
    shared_network: &SharedNetwork,
    invoke_routes: &InvokeRoutes,
) -> bool
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let Some((local_prefix, voters)) = service.steady_raft_voters() else {
        return false;
    };
    if service.replication_id().is_none()
        || voters.is_empty()
        || voters.binary_search(&local_prefix).is_err()
        || !service.stage_replicated_private_ingress(
            request.invocation,
            reference,
            &request.arguments,
        )
    {
        return false;
    }
    let remote_voters = voters
        .iter()
        .copied()
        .filter(|prefix| *prefix != local_prefix)
        .collect::<Vec<_>>();
    if remote_voters.is_empty() {
        return service.steady_raft_voters() == Some((local_prefix, voters));
    }
    let Some(network) = shared_network
        .lock()
        .ok()
        .and_then(|network| network.clone())
    else {
        return false;
    };
    if crate::network::derive_node_prefix(&network.peer_id()) != local_prefix {
        return false;
    }
    let deadline = Instant::now() + SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT;
    let mut peers = Vec::with_capacity(remote_voters.len());
    for (index, prefix) in remote_voters.iter().copied().enumerate() {
        let remaining_voters = remote_voters.len().saturating_sub(index).max(1) as u32;
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .checked_div(remaining_voters)
            .unwrap_or_default();
        let Some(member) =
            lookup_node_member_from_routes_with_timeout(invoke_routes, prefix, budget)
        else {
            return false;
        };
        let Ok(peer) = libp2p::PeerId::from_bytes(&member.key) else {
            return false;
        };
        if !node_member_authenticates_active_slot(&member, prefix, &peer) {
            return false;
        }
        peers.push(peer);
    }
    let replication_id = service
        .replication_id()
        .expect("Raft private ingress has a replication id");
    let mut replies = peers
        .into_iter()
        .map(|peer| {
            network.send_store_private_ingress(
                peer,
                replication_id,
                request.invocation.0,
                reference.hash.0,
                reference.len,
                request.arguments.clone(),
            )
        })
        .collect::<Vec<_>>();
    if replies.iter_mut().any(|reply| {
        reply
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()
            != Some(true)
    }) {
        return false;
    }
    // Leadership or membership changing after staging is safe only if the
    // request is refused. The join path shares the admission barrier, while
    // this final comparison also closes leadership-transfer races.
    service.steady_raft_voters() == Some((local_prefix, voters))
}

/// Shared map of raft-hosted agents: ServiceId word → replication
/// group of the multi-mode worker spawned for it. The companion to
/// `InvokeRoutes` for leader forwarding: where `InvokeRoutes`
/// answers "which channel reaches this ServiceId?", this answers
/// "which Raft group does it belong to?" so [`route_invoke`] can
/// consult the local worker's role/leader-hint when the local
/// replica drops a write.
#[cfg(all(feature = "network", feature = "storage"))]
type RaftHosts = Arc<Mutex<HashMap<u32, [u8; 32]>>>;

/// Type-erased completion of one prepared service Raft root. The promotion worker
/// owns the concrete durable backend and root service until final membership
/// is locally visible, then hands this closure back to the router thread for
/// the short mutable-node publication step.
#[cfg(all(feature = "network", feature = "storage"))]
type PendingRootReady = Box<dyn FnOnce(&mut VosNode) + Send>;

#[cfg(all(feature = "network", feature = "storage"))]
struct NodeCommittedImageStore<B>(Arc<Mutex<B>>);

#[cfg(all(feature = "network", feature = "storage"))]
impl<B> Clone for NodeCommittedImageStore<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
impl<B: crate::service::CommittedImageStore> crate::service::CommittedImageStore
    for NodeCommittedImageStore<B>
{
    type Error = B::Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.lock().unwrap().load()
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.lock().unwrap().commit(image)
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
impl<B> crate::service::ProofArtifactStore for NodeCommittedImageStore<B>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    type Error = <B as crate::service::CommittedImageStore>::Error;

    fn load_proof(
        &self,
        reference: &crate::service::BlobRef,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.lock().unwrap().load_proof(reference)
    }

    fn commit_proof(
        &mut self,
        reference: &crate::service::BlobRef,
        proof: &[u8],
    ) -> Result<(), Self::Error> {
        self.0.lock().unwrap().commit_proof(reference, proof)
    }

    fn reconcile_proof_artifacts(
        &mut self,
        retained: &[crate::service::BlobRef],
    ) -> Result<(), Self::Error> {
        self.0.lock().unwrap().reconcile_proof_artifacts(retained)
    }

    fn load_private_ingress(
        &self,
        invocation: crate::service::InvocationId,
        reference: &crate::service::BlobRef,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0
            .lock()
            .unwrap()
            .load_private_ingress(invocation, reference)
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        self.0.lock().unwrap().private_ingress_artifact_count()
    }

    fn commit_private_ingress(
        &mut self,
        invocation: crate::service::InvocationId,
        reference: &crate::service::BlobRef,
        arguments: &[u8],
        staging: crate::service::PrivateIngressStaging,
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .unwrap()
            .commit_private_ingress(invocation, reference, arguments, staging)
    }

    fn delete_private_ingress(
        &mut self,
        invocation: crate::service::InvocationId,
    ) -> Result<bool, Self::Error> {
        self.0.lock().unwrap().delete_private_ingress(invocation)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(crate::service::InvocationId, crate::service::BlobRef)],
        terminal: &[crate::service::InvocationId],
    ) -> Result<(), Self::Error> {
        self.0
            .lock()
            .unwrap()
            .reconcile_private_ingresses(retained, terminal)
    }

    fn load_producer_record(
        &self,
        actor: crate::service::ActorId,
        tag: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.lock().unwrap().load_producer_record(actor, tag)
    }

    fn commit_producer_record(
        &mut self,
        actor: crate::service::ActorId,
        tag: &[u8; 32],
        record: &[u8],
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .unwrap()
            .commit_producer_record(actor, tag, record)
    }

    fn delete_producer_record(
        &mut self,
        actor: crate::service::ActorId,
        tag: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        self.0.lock().unwrap().delete_producer_record(actor, tag)
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
enum RaftRecoveryOpenError<E> {
    Log(crate::commit::CommitError),
    Service(crate::service::LocalRootTreeOpenError<E>),
}

#[cfg(all(feature = "network", feature = "storage"))]
struct RaftRecoveryRuntime<B> {
    config: crate::service::LocalRootTreeConfig,
    backend: NodeCommittedImageStore<B>,
    db: Arc<redb::Database>,
    raft_config: crate::raft::RaftConfig,
    worker: Arc<crate::raft::RaftWorker>,
    apply_rx: Arc<Mutex<mpsc::Receiver<u64>>>,
    network: Option<Arc<crate::network::Network>>,
    replication_id: [u8; 32],
    handler: Arc<dyn crate::network::RaftRpcHandler>,
    expected_policy: Option<crate::service::Hash>,
    pending_route: Arc<PrivateIngressRoute>,
    proof_verifier: Option<NodeAttestationProofVerifier>,
    production_trust: Option<Arc<dyn crate::service::ProductionTrust>>,
    /// The persisted configuration cannot prove that this replica is outside
    /// the last committed voter set. This is a retention predicate only: a
    /// speculative configuration may require the worker for quorum recovery
    /// without authorizing publication of the application route.
    retain_replica: bool,
}

#[cfg(all(feature = "network", feature = "storage"))]
impl<B> RaftRecoveryRuntime<B>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        > + Send
        + 'static,
{
    fn open(
        &self,
    ) -> Result<
        crate::service::LocalRootTreeService<NodeCommittedImageStore<B>>,
        RaftRecoveryOpenError<<B as crate::service::CommittedImageStore>::Error>,
    > {
        let log = crate::raft::RaftAccumulateLog::from_shared_worker(
            self.db.clone(),
            self.raft_config.clone(),
            self.worker.clone(),
            self.apply_rx.clone(),
        )
        .map_err(RaftRecoveryOpenError::Log)?;
        match self.production_trust.as_ref() {
            Some(trust) => crate::service::LocalRootTreeService::open_raft_production(
                self.config.clone(),
                self.backend.clone(),
                log,
                trust.clone(),
            ),
            None => crate::service::LocalRootTreeService::open_raft_with_proof_verifier(
                self.config.clone(),
                self.backend.clone(),
                log,
                self.proof_verifier
                    .clone()
                    .unwrap_or_else(service_deny_all_proof_verifier),
            ),
        }
        .map_err(RaftRecoveryOpenError::Service)
    }

    fn cleanup(&self, routes: &PrivateIngressRoutes) {
        if let Some(network) = self.network.as_ref() {
            network.unregister_raft_handler_if(&self.replication_id, &self.handler);
        }
        remove_service_private_ingress_route_if(routes, &self.replication_id, &self.pending_route);
    }

    fn membership_definitively_removed_local_voter(&self) -> bool {
        self.worker.handler().snapshot().is_some_and(|snapshot| {
            snapshot
                .active_config_index
                .is_some_and(|index| index <= snapshot.commit_index)
                && !snapshot.members.contains(&self.raft_config.me)
                && snapshot
                    .joint_old
                    .is_none_or(|members| !members.contains(&self.raft_config.me))
                && snapshot.retirement_final_index.is_none()
        })
    }

    /// Route publication requires stronger evidence than worker retention:
    /// the latest effective configuration must be a committed, final
    /// (non-joint) voter set that contains this replica.
    fn membership_committed_final_local_voter(&self) -> bool {
        self.worker.handler().snapshot().is_some_and(|snapshot| {
            snapshot
                .active_config_index
                .is_some_and(|index| index <= snapshot.commit_index)
                && snapshot.joint_old.is_none()
                && snapshot.members.contains(&self.raft_config.me)
        })
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
struct PreparedRaftRoot<B>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    service: Option<crate::service::LocalRootTreeService<NodeCommittedImageStore<B>>>,
    runtime: RaftRecoveryRuntime<B>,
}

/// Shared host-side reverse map: `local_id` (`id.0 & 0xFFFF`) →
/// installed instance name. The companion to `InvokeRoutes` for the
/// auth path: where `InvokeRoutes` answers "which channel reaches this
/// ServiceId?", this answers "what instance name *is* this ServiceId?"
/// so the libp2p gate ([`NodeService::dispatch_invoke`]) and extension
/// relays (the `EFFECT_ASK` fulfiller) can resolve a
/// target's name for actor-local grant probes and `intra_caps`
/// enforcement.
///
/// Keyed on the **low 16 bits** because `instance_service_id` hashes the
/// name into the local half and ORs the node prefix into the high half
/// (see `space_registry::instance_service_id`); the name↔local_id
/// relation is therefore prefix-independent — a replica of the same
/// instance on another node shares the entry. Distinct names *can*
/// collide in the ~15-bit local space; the map is last-writer-wins on
/// collision (the registry's id derivation has the same exposure) and
/// `register_*_inner` logs a WARN when an insert overwrites a different
/// name. `RwLock` because reads are hot (every dispatch / relay) and
/// writes happen once per `register`.
type AgentNames = Arc<std::sync::RwLock<HashMap<u16, String>>>;

/// Descriptive metadata for one registered agent, captured at register
/// Time for the generic `__describe` host primitive.
#[derive(Clone)]
struct AgentInfo {
    name: Option<String>,
    /// Effective (post-seal) consistency tier for an actor agent, or
    /// `None` for a native extension (which has no tier). Read by
    /// [`NodeService::dispatch_invoke`] to refuse inbound *remote* calls
    /// to a node-confined agent — see [`Consistency::is_node_confined`].
    consistency: Option<Consistency>,
    /// Whether this agent opted OUT of the device-private network gate
    /// (see [`AgentConfig::network_reachable`]). When `true`, a
    /// `Local`/`Ephemeral` agent still answers remote peer invokes — for
    /// authoritative-but-network-served single-node state (a per-node
    /// authoritative store, a bridge). Ignored for `Crdt`/`Raft` (never
    /// confined).
    network_reachable: bool,
}

/// Shared per-agent shutdown flags (`id.0 → flag`). `Arc<Mutex>` so the
/// network-side [`NodeService`] sees agents registered after
/// `attach_network` — the `__stop` interceptor flips a flag here.
type AgentShutdown = Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>;

/// Shared per-agent descriptive metadata (`id.0 → info`). `Arc<RwLock>`
/// for the same reason as [`AgentShutdown`]; the `__describe`
/// interceptor reads it.
type AgentInfos = Arc<std::sync::RwLock<HashMap<u32, AgentInfo>>>;

thread_local! {
    /// Complete invoke lineage for the service root currently executing on
    /// this thread. The root's native-extension bridge is installed once, but
    /// the lineage is dispatch-local; keeping it thread-local lets a nested
    /// extension → service → extension call retain the upstream extension and
    /// fail its cycle check before either serial worker blocks on the other.
    static SERVICE_NATIVE_EXTENSION_CHAIN: core::cell::RefCell<Vec<u32>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

struct ServiceNativeExtensionChainGuard {
    previous: Vec<u32>,
}

impl ServiceNativeExtensionChainGuard {
    fn stamp(upstream: &[u32], caller: ServiceId) -> Self {
        let mut chain = upstream.to_vec();
        if chain.last().copied() != Some(caller.0) {
            chain.push(caller.0);
        }
        let previous = SERVICE_NATIVE_EXTENSION_CHAIN
            .with(|current| core::mem::replace(&mut *current.borrow_mut(), chain));
        Self { previous }
    }
}

impl Drop for ServiceNativeExtensionChainGuard {
    fn drop(&mut self) {
        SERVICE_NATIVE_EXTENSION_CHAIN.with(|current| {
            *current.borrow_mut() = core::mem::take(&mut self.previous);
        });
    }
}

fn current_service_native_extension_chain(caller: ServiceId) -> Vec<u32> {
    SERVICE_NATIVE_EXTENSION_CHAIN.with(|current| {
        let mut chain = current.borrow().clone();
        if chain.last().copied() != Some(caller.0) {
            chain.push(caller.0);
        }
        chain
    })
}

/// Synchronous bridge used only by service-actor Refine to reach a named
/// native extension. It resolves against the live node roster, rejects
/// non-extension targets, and activates only an explicit matching `intra_cap`.
struct ServiceNativeExtensionInvoker {
    caller: ServiceId,
    consistency: crate::service::ConsistencyMode,
    timeout: Duration,
    caps: Vec<crate::actors::IntraCap>,
    invoke_routes: InvokeRoutes,
    agent_info: AgentInfos,
}

impl crate::service::NativeExtensionInvoker for ServiceNativeExtensionInvoker {
    fn invoke(
        &self,
        target: &str,
        invocation: crate::service::InvocationId,
        payload: &[u8],
    ) -> Result<Vec<u8>, u8> {
        let Some(ceiling) = crate::actors::cap_for(&self.caps, Some(target)) else {
            return Err(crate::actors::run::STATUS_FORBIDDEN);
        };
        if self.consistency != crate::service::ConsistencyMode::Local {
            // Extension state is node-local. A Raft/CRDT Refine retry on a
            // different replica cannot consult the same side-effect journal,
            // while an ephemeral root cannot durably bind the result. Keep the
            // bridge local until an outbox is committed by consensus.
            return Err(crate::actors::run::STATUS_FORBIDDEN);
        }
        let target_id = {
            let infos = self
                .agent_info
                .read()
                .map_err(|_| crate::actors::run::STATUS_PANICKED)?;
            let mut matches = infos.iter().filter_map(|(id, info)| {
                (info.consistency.is_none()
                    && info
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(target)))
                .then_some(*id)
            });
            let target_id = matches.next().ok_or(crate::actors::run::STATUS_NOT_FOUND)?;
            if matches.next().is_some() {
                // Case-insensitive duplicate extension names would otherwise
                // make HashMap iteration choose the dispatch target.
                return Err(crate::actors::run::STATUS_PANICKED);
            }
            target_id
        };
        let chain = current_service_native_extension_chain(self.caller);
        match check_invoke_forward(&chain, target_id) {
            InvokeForwardCheck::Allowed => {}
            InvokeForwardCheck::Cycle | InvokeForwardCheck::DepthExceeded => {
                return Err(crate::actors::run::STATUS_PANICKED);
            }
        }
        let tx = self
            .invoke_routes
            .lock()
            .map_err(|_| crate::actors::run::STATUS_PANICKED)?
            .get(&target_id)
            .cloned()
            .ok_or(crate::actors::run::STATUS_NOT_FOUND)?;
        let control = NativeCallControl::new(self.timeout);
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(InvokeRequest {
            caller: crate::actors::Caller::Actor(self.caller),
            space_role: Some(ceiling.as_u8()),
            actor_local_role: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: Some(invocation),
            native_call: Some(control.clone()),
            msg: payload.to_vec(),
            reply: ReplyChannel::Sync(reply_tx),
            chain,
        })
        .map_err(|_| crate::actors::run::STATUS_NOT_FOUND)?;
        let envelope = match reply_rx
            .recv_timeout(control.deadline.saturating_duration_since(Instant::now()))
        {
            Ok(envelope) => envelope,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(crate::actors::run::STATUS_PANICKED);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if control.cancel_queued() => {
                // The worker can no longer claim this request, so returning is
                // safe even though its canceled envelope remains in the queue.
                return Err(crate::actors::run::STATUS_PANICKED);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The worker already owns the request. There is no safe way to
                // interrupt an in-process cdylib while it may be performing an
                // external side effect, so retain the receiver until the real
                // durable result (or worker disconnect) arrives.
                reply_rx
                    .recv()
                    .map_err(|_| crate::actors::run::STATUS_PANICKED)?
            }
        };
        unwrap_invoke_envelope_result(&envelope)
    }
}

/// Render one agent's [`AgentInfo`] + live `running` flag as the JSON
/// object the `__describe` primitive replies with (hand-built — vos has
/// no `serde_json` dep). Shape:
/// `{"id":N,"name":"…","running":bool}`.
fn describe_agent_json(id: u32, info: &AgentInfo, running: bool) -> String {
    let name = json_escape(info.name.as_deref().unwrap_or(""));
    format!("{{\"id\":{id},\"name\":\"{name}\",\"running\":{running}}}")
}

/// Minimal JSON string escaper for the handful of fields `__describe`
/// emits (agent names + listen addresses). Escapes the two characters
/// that would break a JSON string literal; other control characters are
/// not expected in manifest-derived identifiers.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Mask a (possibly prefix-scoped) `ServiceId` value down to its
/// prefix-independent local id — the key space of [`AgentNames`].
fn local_id_of(svc_id: u32) -> u16 {
    (svc_id & 0xFFFF) as u16
}

/// Thread-safe handle for invoking local services. Returned by
/// [`VosNode::invoke_handle`] so background tasks can keep
/// calling into the node while [`VosNode::run_forever`] holds
/// the main thread.
///
/// Local-only — cross-node invokes need the attached network,
/// which lives on `VosNode` proper. Drop this handle when the
/// background task is done; the node's lifetime is unaffected.
pub struct InvokeHandle {
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
}

/// Thread-safe host handle used by built-in ingress adapters.
///
/// Protocol adapters authenticate a request first, then invoke through this
/// handle with the resulting [`SubjectId`](crate::service::SubjectId). This
/// keeps bearer material outside actor arguments and preserves the same member
/// origin through local, CRDT, and Raft execution.
#[derive(Clone)]
#[cfg_attr(
    not(any(feature = "http-ingress", feature = "ssh-ingress")),
    allow(dead_code)
)]
pub struct IngressHandle {
    invoke_routes: InvokeRoutes,
    service_actor_routes: Arc<RwLock<HashMap<crate::service::ActorId, ActorRoute>>>,
    service_invocation_seed: [u8; 32],
    service_invocation_ordinal: Arc<AtomicU64>,
    agent_names: AgentNames,
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "network")]
    shared_network: SharedNetwork,
    #[cfg(feature = "ssh-ingress")]
    ingress_node_attester: Option<IngressNodeAttester>,
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_agent_supervisor: Arc<RwLock<Option<crate::agent::production_owner::CleanAgentIngress>>>,
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_agent_recovering: Arc<AtomicBool>,
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    clean_local_lifecycle_queue: Arc<crate::agent::local_lifecycle::LocalLifecycleQueue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressAuthenticationError {
    Invalid,
    AuthorityUnavailable,
}

/// Failure to configure or use the narrowly scoped SSH node-attestation
/// boundary.
#[cfg(feature = "ssh-ingress")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressNodeAttestationError {
    InvalidNode,
    AlreadyConfigured,
    NotConfigured,
    InvalidCredential,
    SigningFailed,
    InvalidQuery(crate::agent::sdk::authority::AuthorityActorProtocolError),
}

#[cfg(feature = "ssh-ingress")]
impl std::fmt::Display for IngressNodeAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SSH ingress node attestation failed: {self:?}")
    }
}

#[cfg(feature = "ssh-ingress")]
impl std::error::Error for IngressNodeAttestationError {}

#[cfg_attr(
    not(any(feature = "http-ingress", feature = "ssh-ingress")),
    allow(dead_code)
)]
impl IngressHandle {
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn clean_agent_recovering(&self) -> bool {
        self.clean_agent_recovering.load(Ordering::Acquire)
    }
    #[cfg(all(test, feature = "network", feature = "storage", target_os = "linux"))]
    pub(crate) fn set_clean_agent_recovering_for_test(&self, recovering: bool) {
        self.clean_agent_recovering
            .store(recovering, Ordering::Release);
    }
    /// Resolve a proven API key against the currently attached clean Authority.
    /// Unlike the legacy credential-id lookup, this signs an exact projection
    /// query and never searches service_actor_routes or falls back to them.
    #[cfg(all(
        feature = "http-ingress",
        feature = "network",
        feature = "storage",
        target_os = "linux"
    ))]
    pub(crate) fn authenticate_clean_api(
        &self,
        credential: &crate::ingress::ApiAccessCredential,
        nonce: crate::agent::sdk::Hash,
    ) -> Result<
        crate::agent::sdk::authority::AuthorityCredentialProjection,
        IngressAuthenticationError,
    > {
        let authority = self
            .clean_agent_supervisor
            .read()
            .ok()
            .and_then(|ingress| ingress.as_ref().map(|ingress| ingress.authority.clone()))
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        let target = authority
            .authority_target()
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?;
        let query = credential
            .sign_projection_query(
                target,
                nonce,
                crate::agent::sdk::authority::AuthorityProjectionSelector::Credential,
            )
            .map_err(|_| IngressAuthenticationError::Invalid)?;
        self.query_clean_credential(query)
    }

    /// Query only the API credential signing this exact clean projection. The
    /// live Authority checks enrollment/status; transport verification alone
    /// is not permission. No legacy bearer credential is consulted here.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn query_clean_credential(
        &self,
        query: crate::agent::sdk::authority::AuthorityProjectionQuery,
    ) -> Result<
        crate::agent::sdk::authority::AuthorityCredentialProjection,
        IngressAuthenticationError,
    > {
        use crate::agent::sdk::authority::{
            AuthorityCredentialProjection, AuthorityProjectionSelector,
        };
        use crate::agent::sdk::wire::CanonicalWire as _;
        if query.selector != AuthorityProjectionSelector::Credential
            || query
                .verify_api_with(&crate::agent::clean_bootstrap::RawCredentialVerifier)
                .is_err()
        {
            return Err(IngressAuthenticationError::Invalid);
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Err(IngressAuthenticationError::AuthorityUnavailable);
        }
        let authority = self
            .clean_agent_supervisor
            .read()
            .ok()
            .and_then(|ingress| ingress.as_ref().map(|ingress| ingress.authority.clone()))
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        let bytes = authority
            .authority_projection_bounded(query.clone())
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?;
        let projection = AuthorityCredentialProjection::decode(&bytes)
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?;
        if projection.query != query {
            return Err(IngressAuthenticationError::AuthorityUnavailable);
        }
        Ok(projection)
    }

    /// Read one response-bound Agent/replica or combined inventory page through the live
    /// Authority. Pages are discovery, not management approval or finality.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn query_clean_agent_inventory(
        &self,
        query: crate::agent::sdk::authority::AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, IngressAuthenticationError> {
        use crate::agent::sdk::authority::{
            AuthorityAgentProjectionPage, AuthorityAgentReplicaProjectionPage,
            AuthorityInventoryProjectionPage, AuthorityProjectionSelector,
        };
        use crate::agent::sdk::wire::CanonicalWire as _;
        if !matches!(
            query.selector,
            AuthorityProjectionSelector::Agents { .. }
                | AuthorityProjectionSelector::AgentReplicas { .. }
                | AuthorityProjectionSelector::Inventory { .. }
        ) || query
            .verify_api_with(&crate::agent::clean_bootstrap::RawCredentialVerifier)
            .is_err()
        {
            return Err(IngressAuthenticationError::Invalid);
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Err(IngressAuthenticationError::AuthorityUnavailable);
        }
        let authority = self
            .clean_agent_supervisor
            .read()
            .ok()
            .and_then(|ingress| ingress.as_ref().map(|ingress| ingress.authority.clone()))
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        let bytes = authority
            .authority_projection_bounded(query.clone())
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?;
        let bound = match query.selector {
            AuthorityProjectionSelector::Agents { .. } => {
                AuthorityAgentProjectionPage::decode(&bytes).is_ok_and(|page| page.query == query)
            }
            AuthorityProjectionSelector::AgentReplicas { .. } => {
                AuthorityAgentReplicaProjectionPage::decode(&bytes)
                    .is_ok_and(|page| page.query == query)
            }
            AuthorityProjectionSelector::Inventory { .. } => {
                AuthorityInventoryProjectionPage::decode(&bytes)
                    .is_ok_and(|page| page.credential.query == query)
            }
            _ => false,
        };
        if !bound {
            return Err(IngressAuthenticationError::AuthorityUnavailable);
        }
        Ok(bytes)
    }

    /// Queue one bounded Local Create for the node owner. Queue acceptance is
    /// not authorization or application success: await the returned result.
    /// Disconnecting does not cancel an accepted durable lifecycle operation.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn create_clean_local_agent(
        &self,
        descriptor: crate::agent::sdk::AgentDescriptor,
        call: crate::agent::sdk::authority::AuthorityCredentialCall,
        runtime: crate::agent::package_admission::AdmittedRuntimePackage,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::LocalCreateResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        use crate::agent::local_lifecycle::LocalLifecycleIngressError;
        use crate::agent::sdk::wire::CanonicalWire as _;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(LocalLifecycleIngressError::Unavailable);
        }
        if descriptor.validate().is_err() || call.encode().is_err() {
            return Err(LocalLifecycleIngressError::Invalid);
        }
        self.clean_local_lifecycle_queue
            .submit(descriptor, call, runtime)
    }

    /// Queue an authenticated Install frame. Acceptance is not application
    /// success; disconnection does not cancel accepted durable work.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn install_clean_local_actor(
        &self,
        submission: crate::agent::local_lifecycle::LocalInstallSubmission,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::LocalInstallResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue.submit_install(submission)
    }

    /// Queue one exact signed ordinary Shared Create. Acceptance is not
    /// authorization, endorsement or application; await the returned result.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn create_clean_shared_agent(
        &self,
        submission: crate::agent::local_lifecycle::SharedCreateSubmission,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::SharedCreateResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue
            .submit_shared_create(submission)
    }

    /// Queue one exact signed ordinary Shared Install. Disconnection does not
    /// cancel accepted durable work; retain the frame for an exact retry.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn install_clean_shared_actor(
        &self,
        submission: crate::agent::local_lifecycle::SharedInstallSubmission,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::SharedInstallResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue
            .submit_shared_install(submission)
    }

    /// Queue a signed call for durable native clock capture. Queue acceptance
    /// itself is not durable; the caller must retain the exact AOC5 for retry.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn prepare_clean_agent_operation(
        &self,
        call: crate::agent::sdk::authority_operation::AuthorityOperationCall,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::AuthorityOperationPreparationResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue.prepare_operation(call)
    }

    /// Queue a signed admin draft. This does not authenticate a transport or
    /// grant permission; the native owner and Authority verify its node binding.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn prepare_clean_authority_admin(
        &self,
        draft: crate::agent::sdk::authority::AuthorityAdminCall,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::AuthorityAdminPreparationResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue.prepare_admin(draft)
    }

    /// Queue exact signed admin work. Dropping the receiver does not cancel
    /// accepted work; retain the call and preparation for ambiguous retries.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn submit_clean_authority_admin(
        &self,
        call: crate::agent::sdk::authority::AuthorityAdminCall,
        preparation: crate::agent::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::AuthorityAdminSubmissionResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue
            .submit_admin(call, preparation)
    }

    /// Queue exact signed authorization inputs. Queue acceptance is not a policy
    /// decision or durable retention; clients must retain the frame for retry.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn submit_clean_agent_operation(
        &self,
        submission: crate::agent::local_lifecycle::AuthorityOperationSubmission,
    ) -> Result<
        mpsc::Receiver<crate::agent::local_lifecycle::AuthorityOperationResult>,
        crate::agent::local_lifecycle::LocalLifecycleIngressError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::local_lifecycle::LocalLifecycleIngressError::Unavailable);
        }
        self.clean_local_lifecycle_queue
            .submit_operation(submission)
    }

    /// Return the currently exposed clean-generation supervisor. The slot is
    /// populated only after authenticated owner construction and is cleared
    /// before node shutdown begins.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn clean_agent_supervisor(
        &self,
    ) -> Option<crate::agent::supervisor::AgentSupervisorHandle> {
        self.clean_agent_supervisor
            .read()
            .ok()
            .and_then(|ingress| ingress.as_ref().map(|ingress| ingress.supervisor.clone()))
    }

    /// Attest one exact clean system-authority projection query after the SSH
    /// server has proved possession of `credential_public_key`. The stable
    /// request binding is caller-derived and must survive reconnect/retry; an
    /// ephemeral SSH session identifier is not accepted as a substitute.
    #[cfg(feature = "ssh-ingress")]
    pub fn attest_ssh_projection_query(
        &self,
        authority: crate::agent::sdk::authority::AuthorityActorTarget,
        credential_public_key: [u8; 32],
        nonce: crate::agent::sdk::Hash,
        selector: crate::agent::sdk::authority::AuthorityProjectionSelector,
        request_binding: crate::agent::sdk::Hash,
    ) -> Result<crate::agent::sdk::authority::AuthorityProjectionQuery, IngressNodeAttestationError>
    {
        use crate::agent::sdk::authority::{
            AuthorityIngressAuthentication, AuthorityProjectionQuery,
        };

        let credential_key = ed25519_dalek::VerifyingKey::from_bytes(&credential_public_key)
            .map_err(|_| IngressNodeAttestationError::InvalidCredential)?;
        if credential_key.is_weak() {
            return Err(IngressNodeAttestationError::InvalidCredential);
        }
        let attester = self
            .ingress_node_attester
            .as_ref()
            .ok_or(IngressNodeAttestationError::NotConfigured)?;
        let mut query = AuthorityProjectionQuery {
            recovery: None,
            authority,
            credential: crate::agent::sdk::CredentialId::of_public_key(&credential_public_key),
            nonce,
            selector,
            authentication: AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key,
                node: attester.node,
                request_binding,
                signature: [0; 64],
            },
        };
        let signature = (attester.signer)(&query.signing_bytes())
            .filter(|signature| *signature != [0; 64])
            .ok_or(IngressNodeAttestationError::SigningFailed)?;
        query.authentication = AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key,
            node: attester.node,
            request_binding,
            signature,
        };
        query
            .validate_shape()
            .map_err(IngressNodeAttestationError::InvalidQuery)?;
        Ok(query)
    }

    /// Resolve a locally catalogued service root by its operator-visible name.
    /// Remote aliases are intentionally excluded: ingress listeners are
    /// host-local and only expose roots attached to their owning node.
    pub fn resolve_actor(&self, name: &str) -> Option<crate::service::ActorId> {
        let names = self.agent_names.read().ok()?;
        let routes = self.service_actor_routes.read().ok()?;
        routes.iter().find_map(|(actor, route)| {
            if route.authenticated_peer.is_some() {
                return None;
            }
            let local = local_id_of(route.route);
            names
                .get(&local)
                .is_some_and(|candidate| candidate == name)
                .then_some(*actor)
        })
    }

    /// Return the authenticated space identity owning one attached actor.
    /// Ingress adapters use this only to derive space-scoped identifiers;
    /// actor routing still binds the complete service identity separately.
    pub fn actor_space(&self, actor: crate::service::ActorId) -> Option<crate::service::SpaceId> {
        self.service_actor_routes
            .read()
            .ok()?
            .get(&actor)
            .map(|route| route.service.space)
    }

    /// Invoke one canonical actor as an already-authenticated member.
    pub fn invoke_actor(
        &self,
        subject: crate::service::SubjectId,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
        proof_requested: bool,
    ) -> Result<Vec<u8>, crate::actors::client::ClientError> {
        self.invoke_actor_wire(
            crate::actors::Caller::Member(subject),
            target,
            arguments,
            proof_requested,
            None,
        )
    }

    /// Invoke a mutation using a caller-owned stable request key. The same
    /// authenticated subject, target, and key always produce the same durable
    /// invocation ID across retries, process restarts, and Raft leaders.
    pub fn invoke_actor_idempotent(
        &self,
        subject: crate::service::SubjectId,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
        proof_requested: bool,
        ingress: &str,
        key: &str,
    ) -> Result<Vec<u8>, crate::actors::client::ClientError> {
        let invocation = ingress_invocation_id(subject, target, ingress, key);
        self.invoke_actor_wire(
            crate::actors::Caller::Member(subject),
            target,
            arguments,
            proof_requested,
            Some(invocation),
        )
    }

    /// Resolve one credential against the live canonical authority. No result
    /// is cached, so revocation and issuer-role changes take effect on the
    /// next ingress request.
    pub fn authenticate_credential(
        &self,
        credential_id: [u8; 32],
    ) -> Result<crate::IngressAccessStatus, IngressAuthenticationError> {
        use crate::{Decode, Encode};

        let authority = self
            .service_actor_routes
            .read()
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?
            .iter()
            .find_map(|(actor, route)| route.is_role_authority.then_some(*actor))
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        let msg = crate::value::Msg::new("authenticate_access")
            .with("credential_id", credential_id.to_vec());
        let encoded = msg.encode();
        let mut arguments = Vec::with_capacity(encoded.len() + 1);
        arguments.push(crate::value::TAG_DYNAMIC);
        arguments.extend_from_slice(&encoded);
        let reply = self
            .invoke_actor_wire(
                crate::actors::Caller::System,
                authority,
                arguments,
                false,
                None,
            )
            .map_err(|_| IngressAuthenticationError::AuthorityUnavailable)?;
        let value = <crate::value::Value as Decode>::try_decode(&reply)
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        let crate::value::Value::Bytes(status) = value else {
            return Err(IngressAuthenticationError::Invalid);
        };
        if status.is_empty() {
            return Err(IngressAuthenticationError::Invalid);
        }
        let status = <crate::IngressAccessStatus as Decode>::try_decode(&status)
            .ok_or(IngressAuthenticationError::AuthorityUnavailable)?;
        (status.credential_id == credential_id)
            .then_some(status)
            .ok_or(IngressAuthenticationError::Invalid)
    }

    /// Resolve one canonical raw Ed25519 SSH public key against the same live
    /// authority used by bearer ingress. The clean credential identity is
    /// derived from the public key, never from an SSH wrapper or comment.
    #[cfg(feature = "ssh-ingress")]
    pub fn authenticate_ssh_public_key(
        &self,
        public_key: &[u8; 32],
    ) -> Result<crate::IngressAccessStatus, IngressAuthenticationError> {
        self.authenticate_credential(crate::agent::sdk::CredentialId::of_public_key(public_key).0)
    }

    fn invoke_actor_wire(
        &self,
        caller: crate::actors::Caller,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
        proof_requested: bool,
        invocation: Option<crate::service::InvocationId>,
    ) -> Result<Vec<u8>, crate::actors::client::ClientError> {
        use crate::Decode;

        if arguments.first() != Some(&crate::value::TAG_DYNAMIC) {
            return Err(crate::actors::client::ClientError::Decode);
        }
        let message = <crate::value::Msg as Decode>::try_decode(&arguments[1..])
            .ok_or(crate::actors::client::ClientError::Decode)?;
        let binding = self
            .service_actor_routes
            .read()
            .map_err(|_| crate::actors::client::ClientError::Unreachable)?
            .get(&target)
            .cloned()
            .ok_or(crate::actors::client::ClientError::NotFound)?;
        #[cfg(all(feature = "network", feature = "storage"))]
        let deadline = Instant::now()
            .checked_add(binding.invoke_timeout)
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
        let tx = self
            .invoke_routes
            .lock()
            .map_err(|_| crate::actors::client::ClientError::Unreachable)?
            .get(&binding.route)
            .cloned()
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
        let invocation = invocation.unwrap_or_else(|| {
            let ordinal = self
                .service_invocation_ordinal
                .fetch_add(1, Ordering::Relaxed);
            let mut nonce = Vec::with_capacity(72);
            nonce.extend_from_slice(&self.service_invocation_seed);
            nonce.extend_from_slice(&ordinal.to_le_bytes());
            nonce.extend_from_slice(&target.0);
            crate::service::InvocationId::derive(b"vos/node-root-invocation/service", &nonce)
        });
        let ingress = crate::service::RootTreeInvocation {
            invocation,
            target,
            method: message.name,
            arguments,
            proof_requested,
        };
        let ingress_wire = crate::service::ServiceWire::encode(&ingress);
        let reply_rx = send_service_ingress(&tx, &ingress_wire, caller.clone())?;
        let envelope = receive_service_ingress_reply(&reply_rx)?;
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(redirect) = decode_service_raft_redirect(&envelope) {
            let network = self
                .shared_network
                .lock()
                .map_err(|_| crate::actors::client::ClientError::Unreachable)?
                .clone()
                .ok_or(crate::actors::client::ClientError::Unreachable)?;
            if proof_requested {
                let local_route = tx.clone();
                let local_caller = caller.clone();
                let replication_id = binding.replication_id;
                let remote_binding = binding.clone();
                return receive_service_attested_with_exact_redrive(
                    &ingress_wire,
                    redirect,
                    |redirect, ingress| {
                        let Some(replication_id) = replication_id else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        let Some(status) = network.local_raft_status(&replication_id) else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        let Some(deadline) =
                            Instant::now().checked_add(remote_binding.invoke_timeout)
                        else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        send_service_raft_invoke_exact(
                            &network,
                            &self.invoke_routes,
                            &remote_binding,
                            status,
                            redirect.leader_prefix,
                            redirect.origin,
                            true,
                            false,
                            false,
                            ingress,
                            deadline,
                        )
                        .map_or(
                            AttestedRedriveAttempt::Ambiguous,
                            AttestedRedriveAttempt::Reply,
                        )
                    },
                    |ingress| {
                        let Ok(reply) =
                            send_service_ingress(&local_route, ingress, local_caller.clone())
                        else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        match reply.recv() {
                            Ok(envelope) => AttestedRedriveAttempt::Reply(envelope),
                            Err(_) => AttestedRedriveAttempt::Ambiguous,
                        }
                    },
                    || std::thread::sleep(Duration::from_millis(100)),
                );
            }

            let replication_id = binding
                .replication_id
                .ok_or(crate::actors::client::ClientError::Unreachable)?;
            let status = network
                .local_raft_status(&replication_id)
                .ok_or(crate::actors::client::ClientError::Unreachable)?;
            let leader_envelope = send_service_raft_invoke_exact(
                &network,
                &self.invoke_routes,
                &binding,
                status,
                redirect.leader_prefix,
                redirect.origin,
                true,
                false,
                false,
                &ingress_wire,
                deadline,
            )
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
            return decode_host_invoke_envelope(&leader_envelope);
        }
        decode_host_invoke_envelope(&envelope)
    }

    /// Invoke a local host service for metadata discovery. This method never
    /// dispatches actor application work and is unavailable to protocol input.
    pub(crate) fn invoke_host_service(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        InvokeHandle {
            invoke_routes: self.invoke_routes.clone(),
            shutdown: self.shutdown.clone(),
        }
        .invoke_with_timeout(target, msg, timeout)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl InvokeHandle {
    /// Synchronously invoke `target`. Returns `None` when the
    /// target isn't a local service or the call times out.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let tx = {
            let map = self.invoke_routes.lock().ok()?;
            map.get(&target.0).cloned()
        };
        let tx = tx?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(InvokeRequest {
            // Host-side API entry: the embedder calling into the
            // daemon from inside the process. `Caller::System`
            // bypasses role checks via the trust shortcut so
            // host-side bootstrap (admin grant before any peer
            // is enrolled) and test harness calls don't hit the
            // Macro-emitted role gate.
            caller: crate::actors::Caller::System,
            space_role: None,
            actor_local_role: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: None,
            native_call: None,
            msg,
            reply: ReplyChannel::Sync(reply_tx),
            chain: Vec::new(),
        })
        .ok()?;
        // Strip the cross-thread invoke envelope down to reply
        // bytes for host-side callers — see `VosNode::invoke`.
        reply_rx
            .recv_timeout(timeout)
            .ok()
            .and_then(|env| unwrap_invoke_envelope(&env))
    }

    /// `true` once the owning [`VosNode`] has been told to shut
    /// down. Background loops poll this so they exit cleanly.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// Shared pointer to the (optional) attached libp2p network. Agent
/// threads grab a clone at spawn time and check it on every
/// `external_invoke` so a `Network` attached *after* registration
/// still gets used. `None` until [`VosNode::attach_network`] is
/// called.
#[cfg(feature = "network")]
type SharedNetwork = Arc<Mutex<Option<Arc<crate::network::Network>>>>;

/// Single inbound-frame service for the node. Combines what used
/// to be three separate trait impls (invoke / sync / manifest)
/// behind one [`NetworkService`](crate::network::NetworkService)
/// installation. Each method either delegates to a node-owned
/// table (invoke routes, CRDT replicas) or returns the data the
/// host pre-stashed (manifest).
///
/// Constructed in [`VosNode::attach_network`] from the node's
/// already-existing tables; the manifest slot is populated by the
/// host (`vosx space up`) before `attach_network` runs.
#[cfg(feature = "network")]
struct NodeService {
    invoke_routes: InvokeRoutes,
    /// Guest-owned root routes distinguish canonical service Raft delegation from
    /// control-plane Raft forwarding. Only the former consumes delegated origin and
    /// can safely omit the host-role probes.
    service_actor_routes: Arc<RwLock<HashMap<crate::service::ActorId, ActorRoute>>>,
    /// Clone of the node's [`AgentNames`] reverse map, read by
    /// [`Self::dispatch_invoke`] to resolve the target's instance name
    /// for the actor-local grant probe — so an operator-written
    /// actor-local grant enforces for *any* installed agent, not just
    /// the registry.
    agent_names: AgentNames,
    /// Clones of the node's per-agent shutdown flags +
    /// descriptive metadata so the `__stop` / `__describe` interceptor in
    /// [`Self::dispatch_invoke`] can stop/describe ANY agent by id —
    /// generic across actor / service / transport agents.
    agent_shutdown: AgentShutdown,
    agent_info: AgentInfos,
    #[cfg(feature = "storage")]
    replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    /// Route-to-group ownership and live voter membership used to authenticate
    /// the internal Raft origin-delegation envelope.
    #[cfg(feature = "storage")]
    raft_hosts: RaftHosts,
    #[cfg(feature = "storage")]
    service_private_ingress_routes: PrivateIngressRoutes,
    shared_network: SharedNetwork,
    manifest: Arc<OnceLock<crate::network::ManifestReply>>,
    proof_blobs: ProofBlobStore,
    proof_blobs_dir: Option<std::path::PathBuf>,
    /// Program-blob cache dir served over `FetchProgramBlob` — a clone of
    /// [`VosNode::program_blobs_dir`]. `None` serves no program blobs.
    program_blobs_dir: Option<std::path::PathBuf>,
    /// This daemon's operator PeerId bytes (a clone of
    /// [`VosNode::operator_peer`], set at [`VosNode::attach_network`]). The
    /// sole caller [`Self::dispatch_invoke`] admits to a node-confined
    /// target. `None` denies every caller (fail closed).
    operator_peer: Option<Vec<u8>>,
    /// Root/operator signer used only to attest that an exact invite
    /// redemption was durably accepted by the canonical role authority before
    /// it enters the registry CRDT. Non-root operators produce a signature the
    /// registry rejects under its immutable-root check.
    operator_signer: Option<crate::registry::OperatorSigner>,
    /// Per-instance-name `SyncFloor` cache for the sync-serve gate. The
    /// floor is a static install-time property, but resolving it hits the
    /// registry with a blocking probe (up to ~5 s); caching keeps
    /// `FetchHeads`/`FetchNode` cheap under a chatty mesh. Entries expire
    /// after [`SYNC_FLOOR_TTL`] so an `install` that sets a floor is
    /// picked up without a restart.
    #[cfg(feature = "storage")]
    sync_floor_cache: SyncFloorCache,
}

/// Cache of resolved sync floors, keyed by replica instance name.
#[cfg(feature = "storage")]
type SyncFloorCache = Arc<RwLock<HashMap<String, (crate::registry::SyncFloor, Instant)>>>;

/// How long a cached `SyncFloor` stays fresh before it's re-probed.
#[cfg(feature = "storage")]
const SYNC_FLOOR_TTL: Duration = Duration::from_secs(30);

#[cfg(feature = "network")]
impl NodeService {
    #[cfg(feature = "storage")]
    fn target_is_local_service_raft_root(&self, target: u32, target_unscoped: u32) -> bool {
        self.local_service_raft_root_route(target, target_unscoped)
            .is_some()
    }

    #[cfg(feature = "storage")]
    fn local_service_raft_root_route(
        &self,
        target: u32,
        target_unscoped: u32,
    ) -> Option<ActorRoute> {
        self.service_actor_routes
            .read()
            .ok()?
            .values()
            .find(|route| {
                route.consistency == crate::service::ConsistencyMode::Raft
                    && route.authenticated_peer.is_none()
                    && (route.route == target || (route.route & 0xFFFF) == target_unscoped)
            })
            .cloned()
    }

    /// Drive one exact invite through the canonical Raft authority and, only
    /// after its committed `Bool(true)` reply is visible, attach an immutable
    /// root signature to the registry message. The signature becomes part of
    /// the recorded CRDT operation, so replay never trusts a caller-supplied
    /// authority marker or a process-local allowlist.
    #[cfg(feature = "storage")]
    fn attest_registry_invite(&self, mut message: crate::value::Msg) -> Option<Vec<u8>> {
        use crate::actors::codec::{Decode, Encode};
        use crate::service::ServiceWire;

        if message.name != "redeem_invite" {
            return None;
        }
        let token_pub = message.args.get_bytes("token_pub")?;
        let role_byte = message.args.get_u8("role")?;
        let expires_at = message.args.get_u64("expires_at")?;
        let authority_bytes = message.args.get_bytes("authority_replication_id")?;
        let authority_replication_id: [u8; 32] = authority_bytes.as_slice().try_into().ok()?;
        let admin_peer_id = message.args.get_bytes("admin_peer_id")?;
        let admin_sig = message.args.get_bytes("admin_sig")?;
        let admin_signature: [u8; 64] = admin_sig.as_slice().try_into().ok()?;
        let holder_peer_id = message.args.get_bytes("peer_id")?;
        let redeem_sig = message.args.get_bytes("redeem_sig")?;
        let redeem_signature: [u8; 64] = redeem_sig.as_slice().try_into().ok()?;
        let node_sig = message.args.get_bytes("node_sig")?;
        let holder_signature: [u8; 64] = node_sig.as_slice().try_into().ok()?;
        let role = match crate::SpaceRole::from_u8(role_byte) {
            Some(role @ (crate::SpaceRole::Member | crate::SpaceRole::Developer)) => role,
            _ => return None,
        };

        // The anchored space id is guest-owned registry state, not an inbound
        // field the redeemer can substitute.
        let mut space_query = vec![crate::value::TAG_DYNAMIC];
        space_query.extend_from_slice(&crate::value::Msg::new("space_id").encode());
        let space_reply = registry_probe_reply(&self.invoke_routes, space_query)?;
        let crate::value::Value::Bytes(space_bytes) =
            <crate::value::Value as Decode>::try_decode(&space_reply)?
        else {
            return None;
        };
        let space = crate::service::SpaceId(space_bytes.as_slice().try_into().ok()?);
        if space == crate::service::SpaceId([0; 32]) || authority_replication_id == [0; 32] {
            return None;
        }

        let root_service = crate::service::RootServiceId(
            crate::service::Hash::digest(
                b"vos/installed-root-service/service",
                &[
                    &space.0,
                    crate::service::ROLE_AUTHORITY_INSTANCE_.as_bytes(),
                    &authority_replication_id,
                ],
            )
            .0,
        );
        let authority_actor = crate::service::ActorId(
            crate::service::Hash::digest(
                b"vos/installed-root-actor/service",
                &[
                    &root_service.0,
                    crate::service::ROLE_AUTHORITY_INSTANCE_.as_bytes(),
                ],
            )
            .0,
        );
        let route = self
            .service_actor_routes
            .read()
            .ok()?
            .get(&authority_actor)
            .cloned()
            .filter(|route| {
                route.service.space == space
                    && route.service.root_service == root_service
                    && route.consistency == crate::service::ConsistencyMode::Raft
                    && route.replication_id == Some(authority_replication_id)
                    && route.is_role_authority
                    && route.authenticated_peer.is_none()
            })?;

        let redemption = crate::service::RoleAuthorityInviteRedemption {
            space,
            authority_replication_id,
            token_pub: token_pub.as_slice().try_into().ok()?,
            role,
            expires_at,
            admin_peer_id: admin_peer_id.clone(),
            admin_signature,
            holder_peer_id: holder_peer_id.clone(),
            redeem_signature,
            holder_signature,
        };
        let redemption_wire = redemption.encode();
        let mut arguments = vec![crate::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &crate::value::Msg::new(crate::service::ROLE_AUTHORITY_INVITE_METHOD_)
                .with("redemption", redemption_wire.clone())
                .encode(),
        );
        let ingress = crate::service::RootTreeInvocation {
            invocation: crate::service::InvocationId::derive(
                b"vos/invite-authority-redemption/service",
                &redemption_wire,
            ),
            target: authority_actor,
            method: crate::service::ROLE_AUTHORITY_INVITE_METHOD_.into(),
            arguments,
            proof_requested: false,
        };
        let reply = self.invoke_service_authority_route(&route, ingress.encode())?;
        if <crate::value::Value as Decode>::try_decode(&reply).and_then(|value| value.as_bool())
            != Some(true)
        {
            return None;
        }

        let canonical = crate::registry::role_authority_invite_attestation_signed_bytes(
            &space.0,
            &authority_replication_id,
            &token_pub,
            role_byte,
            expires_at,
            &admin_peer_id,
            &admin_sig,
            &holder_peer_id,
            &redeem_sig,
            &node_sig,
        );
        let attestation = self.operator_signer.as_ref()?(&canonical)?;
        // Never preserve a caller-provided value. Only the signature produced
        // after the committed authority reply enters the recorded message.
        message
            .args
            .0
            .retain(|(name, _)| name != "authority_attestation");
        message
            .args
            .0
            .push(("authority_attestation".into(), attestation.into()));
        let mut encoded = vec![crate::value::TAG_DYNAMIC];
        encoded.extend_from_slice(&message.encode());
        Some(encoded)
    }

    #[cfg(feature = "storage")]
    fn invoke_service_authority_route(
        &self,
        route: &ActorRoute,
        ingress: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let tx = self.invoke_routes.lock().ok()?.get(&route.route).cloned()?;
        let deadline = Instant::now().checked_add(route.invoke_timeout)?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(InvokeRequest {
            caller: crate::actors::Caller::System,
            space_role: None,
            actor_local_role: None,
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: None,
            native_call: None,
            msg: ingress.clone(),
            reply: ReplyChannel::Sync(reply_tx),
            chain: Vec::new(),
        })
        .ok()?;
        let envelope = reply_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()?;
        if let Some(redirect) = decode_service_raft_redirect(&envelope) {
            let network = self.shared_network.lock().ok()?.clone()?;
            let status = network.local_raft_status(&route.replication_id?)?;
            return send_service_raft_invoke_exact(
                &network,
                &self.invoke_routes,
                route,
                status,
                redirect.leader_prefix,
                redirect.origin,
                false,
                false,
                false,
                &ingress,
                deadline,
            );
        }
        unwrap_invoke_envelope(&envelope)
    }

    /// Send a synchronous `peer_role` invoke
    /// to the local space-registry and surface the result as the
    /// `AUTH_ROLE_*` byte the gate compares against. Returns
    /// `AUTH_ROLE_NONE` (= "deny") for any of:
    ///
    /// - `caller_peer_id == None` — in-process calls don't have
    ///   a libp2p identity (no current callers, but defensive).
    /// - registry route missing — gate fires before the registry
    ///   boots? bail safe.
    /// - registry reply empty / undecodable.
    ///
    /// Cheap (~1 short round-trip on local mpsc) but a hot
    /// frequent-call surface; the response is the registry's
    /// already-cached in-memory `auth_grants` Vec lookup.
    fn lookup_caller_role(&self, caller_peer_id: Option<&libp2p::PeerId>) -> u8 {
        let Some(peer_id) = caller_peer_id else {
            return AUTH_ROLE_NONE;
        };
        // Build a `peer_role` Msg with the caller's PeerId bytes.
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("peer_role").with("peer_id", peer_id.to_bytes());
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// Probe the local space-registry's `node_role` handler for the
    /// NODE member enrolled at `prefix`. Reply byte: `0` = not enrolled,
    /// `1` = VOTER, `2` = OBSERVER (the registry encodes `role + 1`; see
    /// `space_registry::node_role`). `0` on an unreachable/undecodable
    /// reply — the caller treats that as "deny".
    #[cfg(feature = "network")]
    fn lookup_node_role(&self, prefix: u16) -> u8 {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("node_role").with("prefix", prefix as u64);
        let mut payload = Vec::with_capacity(1 + 16);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload).unwrap_or(0)
    }

    /// Resolve the exact NODE roster row at `prefix`. The compact prefix is
    /// useful for routing and Raft membership arithmetic, but it is not an
    /// authenticated identity: two Noise PeerIds can collide in 16 bits.
    /// Callers making an authority decision must compare `MemberRow::key`
    /// with the full authenticated PeerId as well.
    #[cfg(feature = "storage")]
    fn lookup_node_member(&self, prefix: u16) -> Option<crate::registry::MemberRow> {
        lookup_node_member_from_routes(&self.invoke_routes, prefix)
    }

    /// Read the registry-owned, nonzero space anchor used by every scoped
    /// registry-management signature. It must never come from an inbound
    /// request because sibling spaces may share operator keys and replica ids.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn registry_space_id(&self) -> Option<[u8; 32]> {
        use crate::actors::codec::{Decode, Encode};
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("space_id").encode());
        let reply = registry_probe_reply(&self.invoke_routes, payload)?;
        let Value::Bytes(bytes) = <Value as Decode>::try_decode(&reply)? else {
            return None;
        };
        let space_id: [u8; 32] = bytes.as_slice().try_into().ok()?;
        (space_id != [0; 32]).then_some(space_id)
    }

    /// Membership gate for serving a replica's sync data (heads / nodes),
    /// keyed on the replica's [`SyncFloor`](crate::registry::SyncFloor):
    /// `Public` serves any connected peer; `Member` requires enrollment or a
    /// space read grant; `Private` requires a space read grant. `caller == None`
    /// is refused for every non-public floor.
    #[cfg(feature = "storage")]
    fn sync_serve_allowed(&self, caller_peer_id: Option<&libp2p::PeerId>, name: &str) -> bool {
        use crate::registry::SyncFloor;
        match self.resolve_sync_floor(name) {
            SyncFloor::Public => true,
            SyncFloor::Member => {
                let Some(peer) = caller_peer_id else {
                    return false;
                };
                self.lookup_caller_role(Some(peer)) >= AUTH_ROLE_READONLY
                    || self.caller_is_enrolled_node(peer)
            }
            SyncFloor::Private => caller_peer_id
                .is_some_and(|peer| self.lookup_caller_role(Some(peer)) >= AUTH_ROLE_READONLY),
        }
    }

    /// A node enrolled in the space (voter/observer) IS a space member —
    /// admin-gated `add_node` put it there — so it may sync `Member`-floor
    /// state (the registry it bootstraps from, app CRDTs) even before it
    /// holds a separate READONLY grant. This unwedges the join → sync →
    /// grant order: a joiner enrolled as a voter can pull the registry to
    /// learn the space before an operator grants it a role. `Private`
    /// (`msg-*`) deliberately does NOT accept enrollment here — a voter
    /// isn't automatically a channel reader; that stays grant-based.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn caller_is_enrolled_node(&self, peer: &libp2p::PeerId) -> bool {
        let prefix = crate::network::derive_node_prefix(peer);
        self.lookup_node_member(prefix)
            .is_some_and(|member| node_member_authenticates_active_slot(&member, prefix, peer))
    }

    /// Without both authenticated transport and durable roster state,
    /// enrollment cannot be proven; fall back to the grant-only membership
    /// test.
    #[cfg(not(all(feature = "network", feature = "storage")))]
    fn caller_is_enrolled_node(&self, _peer: &libp2p::PeerId) -> bool {
        false
    }

    /// Resolve a replica's serving floor from its instance name. The two
    /// registries are hardcoded (decision 9): the space registry serves at
    /// `Member` — a joiner redeems by remote invoke (ungated) BEFORE it can
    /// sync, so it holds a grant by the time its `FetchHeads` runs — and
    /// the hyperspace registry at `Public` (the federation surface).
    /// Anonymous / test replicas (empty name) serve openly. Every other
    /// replica's floor is its `AgentRow.sync_role`, probed once and cached
    /// with a short TTL; a probe miss defaults to `Member` — fail toward
    /// gated, never open.
    #[cfg(feature = "storage")]
    fn resolve_sync_floor(&self, name: &str) -> crate::registry::SyncFloor {
        use crate::registry::SyncFloor;
        match name {
            "" => return SyncFloor::Public,
            // The space registry serves at MEMBER (decision 9): its state
            // is served only to a caller the serving node's registry knows
            // as a member (a role grant ≥ READONLY, or an enrolled node).
            // The bootstrap ordering that makes this non-deadlocking: a
            // fresh joiner reaches `redeem_invite` by an ungated remote
            // invoke BEFORE it can sync anything — that grants its NODE key
            // (the sync identity) on the serving node, so its next
            // `FetchHeads` passes this gate. `space up <token>` wires the
            // redeem loop; the grant is checked on the SERVING side, so a
            // joiner's own empty registry is irrelevant.
            REGISTRY_AGENT_NAME => return SyncFloor::Member,
            // The hyperspace (federation) registry stays PUBLIC — it is the
            // separate-trust cross-space surface, deliberately ungated.
            HYPERSPACE_REGISTRY_AGENT_NAME => return SyncFloor::Public,
            _ => {}
        }
        if let Ok(cache) = self.sync_floor_cache.read() {
            if let Some((floor, at)) = cache.get(name) {
                if at.elapsed() < SYNC_FLOOR_TTL {
                    return *floor;
                }
            }
        }
        let floor = self.probe_agent_floor(name).unwrap_or(SyncFloor::Member);
        if let Ok(mut cache) = self.sync_floor_cache.write() {
            cache.insert(name.to_string(), (floor, Instant::now()));
        }
        floor
    }

    /// Probe the registry's `agent(name)` handler and read the row's
    /// `sync_role`. `None` when the registry is unreachable, the agent
    /// isn't installed, or the reply doesn't decode.
    #[cfg(all(feature = "storage", feature = "network"))]
    fn probe_agent_floor(&self, name: &str) -> Option<crate::registry::SyncFloor> {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("service_actor").with("instance_name", name);
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        let reply = registry_probe_reply(&self.invoke_routes, payload)?;
        let lookup = decode_registry_bytes_reply::<crate::registry::AgentLookup>(&reply)?;
        if !lookup.protocol.is_current() {
            return None;
        }
        let row = lookup.row?;
        Some(row.sync_role)
    }

    /// Storage-only build (no network): the floor probe is unavailable, so
    /// gate every non-registry replica at `Member` — the same restrictive
    /// default a probe miss falls back to.
    #[cfg(all(feature = "storage", not(feature = "network")))]
    fn probe_agent_floor(&self, _name: &str) -> Option<crate::registry::SyncFloor> {
        None
    }

    /// Shared probe helper for both auth lookups — sends an
    /// already-encoded dynamic Msg to the registry, decodes the
    /// reply as a single `u8`. Returns `None` if the registry is
    /// unreachable (gate fires before registry boots), the reply
    /// times out, or the reply payload doesn't decode.
    fn probe_registry_for_u8(&self, payload: Vec<u8>) -> Option<u8> {
        registry_probe_u8(&self.invoke_routes, payload)
    }

    /// True only when the local space registry has durably authorized `hash`.
    /// The entitlement survives catalog retags so an installed actor or
    /// replay/proof record can recover its pinned historical package. A
    /// missing, stale, or unreachable registry fails closed so the global
    /// host cache never becomes an open cross-space CAS.
    fn program_hash_authorized(&self, hash: &[u8; 32]) -> bool {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("program_blob_authorized").with("hash", hash.to_vec());
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        let Some(reply) = registry_probe_reply(&self.invoke_routes, payload) else {
            return false;
        };
        decode_registry_bytes_reply::<crate::registry::ProgramBlobAuthorization>(&reply)
            .is_some_and(|decision| decision.protocol.is_current() && decision.authorized)
    }

    /// Resolve a (possibly prefix-scoped) target `ServiceId` value back
    /// to the installed instance name registered for it. Reads the
    /// node's shared [`AgentNames`] reverse map; `None` for ids this
    /// node never registered. Mirror of [`VosNode::agent_name_for`]
    /// over the cloned handle the network service holds.
    fn agent_name_for(&self, svc_id: u32) -> Option<String> {
        self.agent_names
            .read()
            .ok()?
            .get(&local_id_of(svc_id))
            .cloned()
    }

    /// Host-side handler for the reserved `__stop` / `__describe` wire
    /// Methods. Returns `Some(reply_bytes)` when the
    /// invoke's `Msg.name` is one of them (already answered), `None` to let
    /// `dispatch_invoke` forward the invoke normally. The reply matches the
    /// raw-`Value` shape `dispatch_invoke` otherwise returns: empty (→
    /// `Value::Unit` → client renders `null`) for `__stop`, an rkyv
    /// `Value::Str(json)` for `__describe`. Tries the scoped id first, then the
    /// unscoped fallback (a locally-registered agent lives under the low 16
    /// bits) — same two-step lookup as the route table.
    ///
    /// **Authorized**: these are host-enforced control ops that bypass the
    /// target actor's own `#[msg(role=…)]` gate, so they carry their own
    /// space-role check against the caller's grant (`lookup_caller_role`):
    /// `__stop` (privileged — stops an agent) requires **ADMIN**; `__describe`
    /// (reads name/kind/listen-addr) requires any space member (≥ read-only).
    /// An unauthorized caller (incl. an anonymous / non-member peer) gets a
    /// `STATUS_FORBIDDEN` envelope, NOT a silent stop/enumerate. The role
    /// lookup runs only after a reserved name matches, so normal dispatch
    /// pays nothing.
    fn try_intercept_lifecycle(
        &self,
        to: u32,
        to_unscoped: u32,
        msg: &[u8],
        caller_peer_id: Option<&libp2p::PeerId>,
    ) -> Option<Vec<u8>> {
        let name = intercepted_method_name(msg)?;
        match name.as_str() {
            "__stop" => {
                if self.lookup_caller_role(caller_peer_id) < AUTH_ROLE_ADMIN {
                    warn!(target = to, "__stop refused: caller lacks ADMIN role");
                    return Some(forbidden_envelope());
                }
                let stopped = self.stop_agent_id(to)
                    || (to != to_unscoped && self.stop_agent_id(to_unscoped));
                if !stopped {
                    warn!(target = to, "__stop: no agent registered under id");
                }
                // Value::Unit ⇒ empty reply (the client decodes empty as Unit).
                Some(Vec::new())
            }
            "__describe" => {
                if self.lookup_caller_role(caller_peer_id) == AUTH_ROLE_NONE {
                    warn!(
                        target = to,
                        "__describe refused: caller is not a space member"
                    );
                    return Some(forbidden_envelope());
                }
                let json = self.describe_agent_id(to).or_else(|| {
                    (to != to_unscoped)
                        .then(|| self.describe_agent_id(to_unscoped))
                        .flatten()
                });
                match json {
                    Some(j) => Some(crate::Encode::encode(&crate::value::Value::Str(j))),
                    // Unknown agent ⇒ empty (Unit); the CLI surfaces "no such agent".
                    None => Some(Vec::new()),
                }
            }
            _ => None,
        }
    }

    /// Flip one agent's shutdown flag by id (the `__stop` primitive's core).
    /// `false` when no agent is registered under `id`.
    fn stop_agent_id(&self, id: u32) -> bool {
        match self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id).cloned())
        {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// `true` when `to` resolves to a node-confined agent this node
    /// registered (consistency `Local`/`Ephemeral`). Mirrors the
    /// `dispatch_invoke` route lookup's scoped/unscoped fallback. A missing
    /// entry (anonymous, cross-node, or never-registered target) is treated
    /// as *not* confined — the route lookup then handles it normally — so
    /// the gate only ever restricts agents this node knows to be device-
    /// private. See [`Self::dispatch_invoke`].
    fn target_is_node_confined(&self, to: u32, to_unscoped: u32) -> bool {
        let Ok(info) = self.agent_info.read() else {
            return false;
        };
        let entry = info.get(&to).or_else(|| {
            if to != to_unscoped {
                info.get(&to_unscoped)
            } else {
                None
            }
        });
        entry.is_some_and(|i| {
            // A `network_reachable` opt-out keeps an authoritative-but-
            // network-served single-node agent (an authoritative store, a
            // bridge) reachable; only device-private agents stay confined.
            i.consistency.is_some_and(Consistency::is_node_confined) && !i.network_reachable
        })
    }

    /// `true` when `caller` is this daemon's own operator — the CLI identity
    /// that ran `vosx space up` ([`VosNode::set_operator_peer`]). The one
    /// caller admitted to a node-confined agent over the network: the
    /// operator drives their device-local messenger with `vosx messenger …`,
    /// which dials the daemon as a libp2p call from this identity. Fails
    /// closed — an unset operator (`None`), an anonymous caller (`None`), or
    /// any other PeerId (a remote peer, or even a remote admin of the same
    /// space) all return `false` — so confined plaintext never leaves the
    /// device. See [`Self::dispatch_invoke`].
    fn caller_is_operator(&self, caller: Option<&libp2p::PeerId>) -> bool {
        self.operator_peer
            .as_deref()
            .zip(caller)
            .is_some_and(|(op, p)| op == p.to_bytes().as_slice())
    }

    /// Authenticate the node-internal Raft delegation channel. The forwarding
    /// peer must be a member of the exact replication group serving `target`,
    /// and the registry's row for its compact prefix must name the exact
    /// Noise-authenticated PeerId. An arbitrary peer — including one which
    /// deliberately collides in the 16-bit route space — cannot assert a
    /// System/Actor origin. Raft voters are already trusted to replicate the
    /// state machine, so carrying the origin they observed does not enlarge
    /// that trust set.
    #[cfg(feature = "storage")]
    fn caller_is_service_raft_voter(
        &self,
        target: u32,
        target_unscoped: u32,
        caller: &libp2p::PeerId,
    ) -> bool {
        let replication_id = self.raft_hosts.lock().ok().and_then(|hosts| {
            hosts
                .get(&target)
                .or_else(|| hosts.get(&target_unscoped))
                .copied()
        });
        let Some(replication_id) = replication_id else {
            return false;
        };
        let status = self
            .shared_network
            .lock()
            .ok()
            .and_then(|network| network.as_ref()?.local_raft_status(&replication_id));
        let Some(status) = status else {
            return false;
        };
        let prefix = crate::network::derive_node_prefix(caller);
        status.is_active_voter(prefix)
            && self.lookup_node_member(prefix).is_some_and(|member| {
                node_member_authenticates_active_slot(&member, prefix, caller)
            })
    }

    /// Render an agent's describe JSON by id (the `__describe` primitive's
    /// core). `None` when no agent is registered under `id`.
    fn describe_agent_id(&self, id: u32) -> Option<String> {
        let info = self.agent_info.read().ok()?.get(&id).cloned()?;
        let running = self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id).map(|f| !f.load(Ordering::Relaxed)))
            .unwrap_or(true);
        Some(describe_agent_json(id, &info, running))
    }
}

/// Send an already-encoded dynamic `Msg` to the local registry and
/// decode the reply as a single `u8`. The free-function core of the
/// auth probes, shared by [`NodeService::probe_registry_for_u8`] (the
/// libp2p gate) and [`relay_actor_local_role`] (extension relays),
/// which both have the routes table but not a `NodeService`. The probe
/// asserts `Caller::System` so it bypasses any role-gated registry read
/// handler. Returns `None` if the registry is unreachable, the reply
/// times out, or the payload doesn't decode.
#[cfg(feature = "network")]
fn registry_probe_reply(routes: &InvokeRoutes, payload: Vec<u8>) -> Option<Vec<u8>> {
    registry_probe_reply_with_timeout(
        routes,
        payload,
        Duration::from_millis(SERVICE_RAFT_VOTER_AUTH_TIMEOUT_MS),
    )
}

#[cfg(feature = "network")]
fn registry_probe_reply_with_timeout(
    routes: &InvokeRoutes,
    payload: Vec<u8>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if timeout.is_zero() {
        return None;
    }
    let registry_id = crate::abi::service::ServiceId::REGISTRY.local_id() as u32;
    let tx = routes.lock().ok()?.get(&registry_id).cloned()?;
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx
        .send(InvokeRequest {
            caller: crate::actors::Caller::System,
            space_role: None,
            actor_local_role: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: None,
            native_call: None,
            msg: payload,
            reply: ReplyChannel::Sync(reply_tx),
            chain: vec![],
        })
        .is_err()
    {
        return None;
    }
    let envelope = reply_rx.recv_timeout(timeout).ok()?;
    unwrap_invoke_envelope(&envelope)
}

/// Resolve the exact NODE roster row behind one compact Raft slot. Keeping
/// this as a free function lets both inbound delegation and outbound
/// authority redirects apply the same full-PeerId identity check.
#[cfg(all(feature = "network", feature = "storage"))]
fn lookup_node_member_from_routes(
    routes: &InvokeRoutes,
    prefix: u16,
) -> Option<crate::registry::MemberRow> {
    lookup_node_member_from_routes_with_timeout(
        routes,
        prefix,
        Duration::from_millis(SERVICE_RAFT_VOTER_AUTH_TIMEOUT_MS),
    )
}

#[cfg(all(feature = "network", feature = "storage"))]
fn lookup_node_member_from_routes_with_timeout(
    routes: &InvokeRoutes,
    prefix: u16,
    timeout: Duration,
) -> Option<crate::registry::MemberRow> {
    use crate::actors::codec::{Decode, Encode};
    use crate::registry::{MEMBER_KIND_NODE, MemberPage};
    use crate::value::{Msg, TAG_DYNAMIC, Value};

    // `members` resumes strictly *after* its cursor. Starting immediately
    // before `prefix` gives an O(1)-page exact lookup; prefix zero uses the
    // documented empty-cursor start.
    let after_key = prefix
        .checked_sub(1)
        .map(|previous| previous.to_be_bytes().to_vec())
        .unwrap_or_default();
    let msg = Msg::new("members")
        .with("after_kind", MEMBER_KIND_NODE)
        .with("after_key", after_key)
        .with("budget", 1u32);
    let mut payload = Vec::with_capacity(1 + 64);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    let reply = registry_probe_reply_with_timeout(routes, payload, timeout)?;
    let Value::Bytes(bytes) = <Value as Decode>::try_decode(&reply)? else {
        return None;
    };
    let page = <MemberPage as Decode>::try_decode(&bytes)?;
    page.members
        .into_iter()
        .next()
        .filter(|member| member.kind == MEMBER_KIND_NODE && member.prefix == prefix)
}

/// Decode one typed registry response after the outer invoke envelope has
/// been removed. Clean-break lookup responses carry their protocol identity
/// inside this rkyv payload; callers must still check it before using rows.
#[cfg(feature = "network")]
fn decode_registry_bytes_reply<T: crate::actors::codec::Decode>(reply: &[u8]) -> Option<T> {
    use crate::value::Value;

    let value = <Value as crate::actors::codec::Decode>::try_decode(reply)?;
    let Value::Bytes(bytes) = value else {
        return None;
    };
    T::try_decode(&bytes)
}

#[cfg(feature = "network")]
fn registry_probe_u8(routes: &InvokeRoutes, payload: Vec<u8>) -> Option<u8> {
    decode_u8_reply(&registry_probe_reply(routes, payload)?)
}

/// Bind the compact Raft voter slot back to its complete authenticated
/// identity. `expected_prefix` has already passed the replication group's
/// membership check; the registry row supplies the non-truncatable identity
/// needed for delegation authority.
#[cfg(all(feature = "network", feature = "storage"))]
fn node_member_authenticates_active_slot(
    member: &crate::registry::MemberRow,
    expected_prefix: u16,
    peer: &libp2p::PeerId,
) -> bool {
    member.kind == crate::registry::MEMBER_KIND_NODE
        && matches!(
            member.role,
            crate::registry::NODE_ROLE_VOTER | crate::registry::NODE_ROLE_OBSERVER
        )
        && member.prefix == expected_prefix
        && crate::network::derive_node_prefix(peer) == expected_prefix
        && member.key == peer.to_bytes()
}

#[cfg(all(feature = "network", feature = "storage"))]
fn node_member_authenticates_voter(
    member: &crate::registry::MemberRow,
    expected_prefix: u16,
    peer: &libp2p::PeerId,
) -> bool {
    member.role == crate::registry::NODE_ROLE_VOTER
        && node_member_authenticates_active_slot(member, expected_prefix, peer)
}

#[cfg(all(feature = "network", feature = "storage"))]
#[allow(clippy::too_many_arguments)]
fn verifies_raft_voter_replacement_operator(
    operator: &libp2p::PeerId,
    space_id: &[u8; 32],
    replication_id: &[u8; 32],
    old_prefix: u16,
    old_peer: &libp2p::PeerId,
    replacement_prefix: u16,
    replacement_peer: &libp2p::PeerId,
    operation_epoch: u64,
    signature: &[u8; 64],
) -> bool {
    let Some(public_key) = crate::registry::ed25519_pubkey_from_peer_id(&operator.to_bytes())
    else {
        return false;
    };
    let message = crate::registry::raft_voter_replacement_signed_bytes(
        space_id,
        replication_id,
        old_prefix,
        &old_peer.to_bytes(),
        replacement_prefix,
        &replacement_peer.to_bytes(),
        operation_epoch,
    );
    let provider = futures_rustls::rustls::crypto::ring::default_provider();
    let Some(verifier) = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == futures_rustls::rustls::SignatureScheme::ED25519)
        .and_then(|(_, algorithms)| algorithms.first())
    else {
        return false;
    };
    verifier
        .verify_signature(&public_key, &message, signature)
        .is_ok()
}

/// Bind a Raft leader hint to the complete registry-authenticated peer. The
/// network's prefix map is deliberately absent: a colliding connected peer
/// must never participate in authority finality or response selection.
#[cfg(all(feature = "network", feature = "storage"))]
fn authenticated_service_raft_leader_peer(
    status: &crate::network::RaftStatusReply,
    member: &crate::registry::MemberRow,
    leader_prefix: u16,
) -> Option<libp2p::PeerId> {
    if !status.present
        || status.leader_hint != Some(leader_prefix)
        || !status.is_active_voter(leader_prefix)
    {
        return None;
    }
    let peer = libp2p::PeerId::from_bytes(&member.key).ok()?;
    node_member_authenticates_active_slot(member, leader_prefix, &peer).then_some(peer)
}

/// Follow authority redirects without ever entering the network's generic
/// prefix-based redirect path. Every hop is selected from an exact group
/// status and the canonical roster's complete PeerId; a second leadership
/// change is returned here and reauthenticated before another send.
#[cfg(all(feature = "network", feature = "storage"))]
#[allow(clippy::too_many_arguments)]
fn send_service_raft_invoke_exact(
    network: &crate::network::Network,
    invoke_routes: &InvokeRoutes,
    route: &ActorRoute,
    mut status: crate::network::RaftStatusReply,
    mut leader_prefix: u16,
    origin: crate::service::Origin,
    preserve_envelope: bool,
    role_authority_request: bool,
    root_upgrade_request: bool,
    ingress: &[u8],
    deadline: Instant,
) -> Option<Vec<u8>> {
    let replication_id = route.replication_id?;
    let mut visited = std::collections::BTreeSet::new();
    loop {
        if !visited.insert(leader_prefix) {
            return None;
        }
        let member = lookup_node_member_from_routes(invoke_routes, leader_prefix)?;
        let peer = authenticated_service_raft_leader_peer(&status, &member, leader_prefix)?;
        let leader_route = ServiceId::new(leader_prefix, ServiceId(route.route).local_id()).0;
        let delegated = encode_service_raft_delegation(
            origin,
            preserve_envelope,
            role_authority_request,
            root_upgrade_request,
            ingress,
        );
        let response = network
            .send_invoke_exact(
                peer,
                ServiceId::REGISTRY.0,
                leader_route,
                Vec::new(),
                delegated,
            )
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()?;
        match response {
            crate::network::NetworkInvokeResponse::Reply(payload) => return Some(payload),
            crate::network::NetworkInvokeResponse::Redirect {
                leader_prefix: next,
            } => {
                status = network
                    .send_raft_status_req(peer, replication_id)
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .ok()?;
                leader_prefix = next;
            }
        }
    }
}

/// Pull a `u8` out of the actor-framework reply bytes. Handles
/// both the `Value::U8` wire shape and the `Value::Bytes(rkyv(u8))`
/// fallback. The authorization lookup needs this; other host
/// callers stay with the dynamic Value decoder.
#[cfg(feature = "network")]
fn decode_u8_reply(bytes: &[u8]) -> Option<u8> {
    use crate::actors::codec::Decode;
    let value = <crate::value::Value as Decode>::try_decode(bytes)?;
    match value {
        crate::value::Value::U8(n) => Some(n),
        crate::value::Value::U32(n) => Some(n as u8),
        crate::value::Value::U64(n) => Some(n as u8),
        crate::value::Value::Bytes(b) => <u8 as Decode>::try_decode(&b),
        _ => None,
    }
}

/// Decode a dynamic-dispatch message without disturbing the original bytes.
#[cfg(feature = "network")]
fn intercepted_msg(msg: &[u8]) -> Option<crate::value::Msg> {
    use crate::value::TAG_DYNAMIC;
    if msg.first() != Some(&TAG_DYNAMIC) {
        return None;
    }
    <crate::value::Msg as crate::Decode>::try_decode(&msg[1..])
}

/// Bind a catalog mutation's embedded author to the transport identity that
/// actually admitted it. A direct hop compares the complete PeerId bytes. A
/// Raft leader hop receives only the authenticated member subject carried by
/// the voter wrapper, so it compares the canonical subject derived from those
/// same signer bytes. Actor/System origins can never borrow a member's signed
/// catalog request.
#[cfg(feature = "network")]
fn catalog_author_matches_ingress(
    signer: &[u8],
    caller: Option<&libp2p::PeerId>,
    delegated_origin: Option<crate::service::Origin>,
) -> bool {
    match delegated_origin {
        Some(crate::service::Origin::Member(subject)) => {
            crate::service::SubjectId::of_authenticated_peer(signer) == subject
        }
        Some(
            crate::service::Origin::Anonymous
            | crate::service::Origin::Actor(_)
            | crate::service::Origin::System,
        ) => false,
        None => caller.is_some_and(|caller| caller.to_bytes() == signer),
    }
}

/// Peek the dynamic-dispatch `Msg.name` out of an invoke payload
/// (`[TAG_DYNAMIC][rkyv Msg]`) for the lifecycle interceptor, without
/// disturbing the original bytes (they're still forwarded verbatim on a
/// non-match). `None` when the payload isn't a dynamic `Msg` (a raw/typed
/// invoke is never a reserved lifecycle verb) or fails to decode.
#[cfg(feature = "network")]
fn intercepted_method_name(msg: &[u8]) -> Option<String> {
    intercepted_msg(msg).map(|m| m.name)
}

/// Admission-time expiry check for a live inbound redemption. The registry
/// actor deliberately has no clock because it must replay accepted operations
/// deterministically; the serving host is the one place wall time belongs.
#[cfg(feature = "network")]
fn redeem_invite_is_expired(msg: &crate::value::Msg, now: Option<u64>) -> bool {
    if msg.name != "redeem_invite" {
        return false;
    }
    let Some(expires_at) = msg.args.get_u64("expires_at") else {
        return true;
    };
    now.is_none_or(|now| now >= expires_at)
}

/// Apply the same host-time admission check to the service authority's wrapped
/// root-tree invocation. Once admitted, the PVM replays only deterministic
/// signature and delegation checks; wall time never enters actor state.
#[cfg(feature = "network")]
fn authority_invite_is_expired(msg: &[u8], now: Option<u64>) -> bool {
    use crate::service::ServiceWire;

    let Ok(invocation) = crate::service::RootTreeInvocation::decode(msg) else {
        return false;
    };
    if invocation.method != crate::service::ROLE_AUTHORITY_INVITE_METHOD_ {
        return false;
    }
    let Some(arguments) = intercepted_msg(&invocation.arguments) else {
        return true;
    };
    if arguments.name != crate::service::ROLE_AUTHORITY_INVITE_METHOD_ {
        return true;
    }
    let Some(redemption) = arguments.args.get_bytes("redemption") else {
        return true;
    };
    let Ok(redemption) = crate::service::RoleAuthorityInviteRedemption::decode(&redemption) else {
        return true;
    };
    now.is_none_or(|now| now >= redemption.expires_at)
}

#[cfg(feature = "network")]
impl crate::network::NetworkService for NodeService {
    fn dispatch_invoke(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        match self.dispatch_invoke_routed(caller_peer_id, from, to, chain, msg) {
            crate::network::NetworkInvokeResponse::Reply(reply) => reply,
            crate::network::NetworkInvokeResponse::Redirect { .. } => Vec::new(),
        }
    }

    fn dispatch_invoke_routed(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        _from: u32,
        to: u32,
        chain: Vec<u32>,
        mut msg: Vec<u8>,
    ) -> crate::network::NetworkInvokeResponse {
        // The chain arrived already including the original caller's
        // ID (the remote peer's agent). The receiver's own
        // external_invoke prepends *this* agent's ID when dispatching
        // further hops, so we don't need to touch the chain here.
        //
        // Cross-network targets carry the receiver's `node_prefix` in
        // the upper 16 bits. Many agents (notably the well-known
        // registry at local_id 0) register themselves as unscoped
        // (`ServiceId(0, local_id)`), so a literal lookup of `to`
        // misses. Fall back to the unscoped form when the prefix
        // matches our own node — same routing decision the local
        // path makes via `is_on_node || is_local`.
        let to_unscoped = to & 0xFFFF;

        // A follower forwarding a local System/Actor call cannot rely on the
        // new Noise hop for identity: that hop authenticates the follower,
        // not the original caller. Accept its delegated origin only from a
        // current voter of this exact root's Raft group. A local follower
        // proxies that authenticated wrapper to the exact current leader;
        // ordinary remote callers never get to construct it themselves.
        #[cfg(feature = "storage")]
        let (delegated_origin, preserve_envelope, role_authority_request, root_upgrade_request) =
            match decode_service_raft_delegation(&msg) {
                Ok(Some(delegated))
                    if caller_peer_id.as_ref().is_some_and(|peer| {
                        self.caller_is_service_raft_voter(to, to_unscoped, peer)
                    }) =>
                {
                    msg = delegated.ingress;
                    (
                        Some(delegated.origin),
                        delegated.preserve_envelope,
                        delegated.role_authority_request,
                        delegated.root_upgrade_request,
                    )
                }
                Ok(Some(_)) | Err(()) => {
                    warn!(target = to, peer = ?caller_peer_id, "refused unauthenticated Raft origin delegation");
                    return Vec::new().into();
                }
                Ok(None) => (None, false, false, false),
            };
        #[cfg(not(feature = "storage"))]
        let delegated_origin: Option<crate::service::Origin> = None;
        #[cfg(not(feature = "storage"))]
        let preserve_envelope = false;
        #[cfg(not(feature = "storage"))]
        let role_authority_request = false;
        #[cfg(not(feature = "storage"))]
        let root_upgrade_request = false;
        #[cfg(feature = "storage")]
        let authenticated_raft_delegation =
            delegated_origin.is_some() && self.target_is_local_service_raft_root(to, to_unscoped);
        #[cfg(not(feature = "storage"))]
        let authenticated_raft_delegation = false;

        // Catalog mutations carry their author's signature before they reach
        // the host. Bind that embedded signer to the Noise-authenticated
        // caller on the first hop, or to the original authenticated member
        // carried by an accepted voter delegation on the leader hop. The
        // payload remains byte-for-byte unchanged for recording and replay.
        if to_unscoped == ServiceId::REGISTRY.local_id() as u32 {
            match crate::registry::catalog_op_auth_signer(&msg) {
                Ok(None) => {}
                Ok(Some(signer))
                    if catalog_author_matches_ingress(
                        &signer,
                        caller_peer_id.as_ref(),
                        delegated_origin,
                    ) => {}
                Ok(Some(_)) | Err(()) => {
                    warn!(peer = ?caller_peer_id, "catalog mutation author does not match authenticated ingress");
                    return forbidden_envelope().into();
                }
            }
        }

        // Expiry is checked once, on the serving host, before the operation is
        // admitted into the registry DAG. The signed deadline is re-verified
        // by the actor; replay never consults wall time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        let expired_registry_invite = to_unscoped == ServiceId::REGISTRY.local_id() as u32
            && intercepted_msg(&msg).is_some_and(|decoded| redeem_invite_is_expired(&decoded, now));
        let expired_authority_invite = self
            .agent_name_for(to_unscoped)
            .as_deref()
            .is_some_and(|name| name == crate::service::ROLE_AUTHORITY_INSTANCE_)
            && authority_invite_is_expired(&msg, now);
        if expired_registry_invite || expired_authority_invite {
            warn!(peer = ?caller_peer_id, "redeem_invite refused: token expired");
            return forbidden_envelope().into();
        }

        // A registry invite is never admitted directly from network bytes.
        // First execute the exact redemption in the canonical Raft authority;
        // then replace any caller-supplied attestation with the immutable
        // root's signature over that accepted operation. The registry records
        // this signature in its CRDT node and deterministically re-verifies it
        // on every replay.
        if to_unscoped == ServiceId::REGISTRY.local_id() as u32
            && intercepted_msg(&msg).is_some_and(|decoded| decoded.name == "redeem_invite")
        {
            #[cfg(feature = "storage")]
            match intercepted_msg(&msg).and_then(|decoded| self.attest_registry_invite(decoded)) {
                Some(attested) => msg = attested,
                None => {
                    warn!(peer = ?caller_peer_id, "redeem_invite refused: canonical authority did not attest acceptance");
                    return forbidden_envelope().into();
                }
            }
            #[cfg(not(feature = "storage"))]
            {
                return forbidden_envelope().into();
            }
        }

        // Locality boundary: a node-confined agent (`Local`/`Ephemeral`)
        // holds device-private state — for the messenger, the MLS keys, the
        // CSPRNG seed and the decrypted plaintext history. The ONLY network
        // caller allowed to reach it is this daemon's own operator: the
        // device's human drives their messenger with `vosx messenger …`,
        // which dials the daemon as a libp2p call carrying the operator's CLI
        // identity (`Caller::Peer(<operator>)`). Every other peer is refused
        // — without this gate one could compute the name-derived ServiceId
        // and call `history` (read another node's plaintext), `seed` (inject
        // a known CSPRNG root) or `send`/`invite` (impersonate the member),
        // and a remote ADMIN of the same space is refused just the same: the
        // boundary is the device, not the space role. Refuse as if the agent
        // did not exist (empty reply — no existence oracle, matching the
        // unknown-target path below). Runs ahead of the lifecycle interceptor
        // so `__stop`/`__describe` of a confined agent are refused too. In-
        // process host calls (`VosNode::invoke` / `InvokeHandle`) never reach
        // this method, so local provisioning is unaffected.
        if self.target_is_node_confined(to, to_unscoped)
            && !self.caller_is_operator(caller_peer_id.as_ref())
        {
            warn!(
                target = to,
                peer = ?caller_peer_id,
                "invoke refused: node-confined agent is reachable only by this \
                 device's operator",
            );
            return Vec::new().into();
        }

        // Reserved generic lifecycle methods are answered
        // host-side, so `vosx <agent> stop|describe` works for any agent even
        // when it has no matching `#[msg]` handler. The method name lives inside
        // the rkyv `Msg`; this is the one place the host peeks it. The `__`
        // prefix keeps `__stop`/`__describe` from colliding with an actor's own
        // handler names, keeping lifecycle uniform across all hosted targets.
        // It carries its OWN space-role gate (admin for stop, member for
        // describe) since it bypasses the target actor's `#[msg(role)]` check.
        if let Some(reply) =
            self.try_intercept_lifecycle(to, to_unscoped, &msg, caller_peer_id.as_ref())
        {
            return reply.into();
        }

        // The dispatch-layer role gate has moved to the actor's own
        // macro-emitted #[msg(role = X)] check
        // runs at the dispatch boundary inside the agent and
        // surfaces STATUS_FORBIDDEN through the wire envelope
        // (see vos/src/actors/lifecycle.rs::exit_status + the
        // runtime's last_status plumbing). The host stays
        // generic: it ferries the caller bytes; the actor
        // decides.

        let tx = self.invoke_routes.lock().ok().and_then(|m| {
            m.get(&to).cloned().or_else(|| {
                if to != to_unscoped {
                    m.get(&to_unscoped).cloned()
                } else {
                    None
                }
            })
        });
        let Some(tx) = tx else {
            return Vec::new().into();
        };
        #[cfg(feature = "storage")]
        let raft_redrive = self
            .local_service_raft_root_route(to, to_unscoped)
            .map(|route| (route, msg.clone()));
        let (reply_tx, reply_rx) = mpsc::channel();
        // libp2p noise verified the PeerId at connect time; the
        // multihash bytes are what the registry's grant table
        // keys on. `None` (in-process libp2p frame with no peer)
        // collapses to Unauthenticated.
        let caller = match caller_peer_id.as_ref() {
            Some(p) => crate::actors::Caller::Peer(p.to_bytes()),
            None => crate::actors::Caller::Unauthenticated,
        };
        // Populate the space role for Peer callers. Actor-specific service
        // roles are authenticated inside the service protocol, not through
        // the control-plane registry.
        let (space_role, actor_local_role) = if authenticated_raft_delegation {
            // The full-PeerId voter check above is the authority boundary for
            // authenticated delegation. The canonical service root ingress accepts only public methods
            // and consumes `delegated_origin`, not host role bytes. Re-probing
            // the forwarding node's space/actor roles is therefore both
            // semantically irrelevant and two extra serial 5-second waits.
            // Keep both absent so a future non-public service cutover fails closed
            // until it carries its own authenticated authorization evidence.
            (None, None)
        } else {
            match &caller {
                crate::actors::Caller::Peer(_) => {
                    let space = self.lookup_caller_role(caller_peer_id.as_ref());
                    ((space != AUTH_ROLE_NONE).then_some(space), None)
                }
                // Unauthenticated has no grant lookups; intra-system
                // Actor callers bypass via the Context::has_role
                // short-circuit.
                _ => (None, None),
            }
        };

        // Private-replica read gate. A `Private`-floor replica (the
        // messenger's `msg-*` channel actors, or any app agent installed
        // `sync = "private"`) holds state the sync gate serves only to
        // members/grantees, and its READ handlers are bare `#[msg]` (no
        // role gate). The local owner reads its OWN replica through the
        // same-node invoke route and never reaches `dispatch_invoke`, so a
        // read arriving HERE is always a remote peer. Gate it by the same
        // membership floor the sync path uses ([`sync_serve_allowed`]): a
        // space member may read; a
        // non-member is refused as if the method did not exist (empty
        // reply — no existence oracle). This only closes the invoke
        // backdoor that bypassed the sync gate. WRITE handlers (raft
        // leader-forward of `post` / `commit` / `publish_kp` / …) are NOT
        // gated here — they carry the actor's own `#[msg(role = …)]` check
        // and legitimately arrive over the network. Reuses the role bytes
        // already probed above; the floor lookup is cached.
        #[cfg(feature = "storage")]
        let target_is_private = self.agent_name_for(to_unscoped).is_some_and(|name| {
            self.resolve_sync_floor(&name) == crate::registry::SyncFloor::Private
        });
        #[cfg(not(feature = "storage"))]
        let target_is_private = false;
        if target_is_private
            && intercepted_method_name(&msg).is_some_and(|m| is_private_read_method(&m))
        {
            let is_member = space_role.is_some_and(|r| r >= AUTH_ROLE_READONLY);
            if !is_member {
                warn!(
                    target = to,
                    peer = ?caller_peer_id,
                    "invoke refused: private replica read requires space membership",
                );
                return Vec::new().into();
            }
        }

        if tx
            .send(InvokeRequest {
                caller,
                space_role,
                actor_local_role,
                #[cfg(all(feature = "network", feature = "storage"))]
                delegated_origin,
                role_authority_request,
                root_upgrade_request,
                invocation_id: None,
                native_call: None,
                msg,
                reply: ReplyChannel::Sync(reply_tx),
                chain,
            })
            .is_err()
        {
            return Vec::new().into();
        }
        // The receiver replies with the full invoke envelope; the
        // libp2p protocol still ships only reply bytes, so unwrap
        // here. A future protocol bump can carry the envelope so
        // remote yielded children become drivable cross-node.
        //
        // STATUS_FORBIDDEN envelopes are preserved verbatim
        // so the client-side `is_forbidden_envelope` peek
        // surfaces ClientError::Forbidden ("permission denied").
        // Without this passthrough, the unwrap collapses the
        // refusal to an empty reply that vosx mis-decodes as
        // Value::Unit.
        //
        // Timeout budget mirrors the libp2p request_response side
        // (5 min) so slow handlers like the dev extension's
        // `compile` (cargo + rustc) don't get cut off here while
        // the wire layer is still patient.
        match reply_rx.recv_timeout(Duration::from_secs(300)).ok() {
            Some(env) => {
                #[cfg(feature = "storage")]
                if let Some(redirect) = decode_service_raft_redirect(&env) {
                    // A one-shot client normally knows only the daemon it
                    // dialled. Returning a compact leader prefix asks that
                    // unauthenticated client-side map to discover and trust a
                    // different peer which it may never have connected to.
                    // The follower already has the authenticated Raft group
                    // and canonical NODE roster, so proxy the exact ingress
                    // while delegating the origin the guest just derived.
                    if let Some((route, ingress)) = raft_redrive {
                        let forwarded = self
                            .shared_network
                            .lock()
                            .ok()
                            .and_then(|network| network.clone())
                            .and_then(|network| {
                                let replication_id = route.replication_id?;
                                let status = network.local_raft_status(&replication_id)?;
                                let deadline = Instant::now().checked_add(route.invoke_timeout)?;
                                send_service_raft_invoke_exact(
                                    &network,
                                    &self.invoke_routes,
                                    &route,
                                    status,
                                    redirect.leader_prefix,
                                    redirect.origin,
                                    preserve_envelope,
                                    role_authority_request,
                                    redirect.root_upgrade_request || root_upgrade_request,
                                    &ingress,
                                    deadline,
                                )
                            });
                        return forwarded.unwrap_or_default().into();
                    }
                    return crate::network::NetworkInvokeResponse::Redirect {
                        leader_prefix: redirect.leader_prefix,
                    };
                }
                if preserve_envelope {
                    return env.into();
                }
                if env.first().copied() == Some(crate::actors::run::STATUS_FORBIDDEN) {
                    let peer_label = caller_peer_id
                        .as_ref()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "<local>".into());
                    warn!(
                        target = to,
                        peer = %peer_label,
                        "auth: actor refused call — caller lacks the required role",
                    );
                    return forbidden_envelope().into();
                }
                unwrap_invoke_envelope(&env).unwrap_or_default().into()
            }
            None => Vec::new().into(),
        }
    }

    #[cfg(feature = "storage")]
    fn sync_roots(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        replication_id: &[u8; 32],
    ) -> Option<Vec<[u8; 32]>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        if !self.sync_serve_allowed(caller_peer_id.as_ref(), &slot.name) {
            return None;
        }
        crate::commit::read_roots(&slot.db).ok()
    }

    #[cfg(feature = "storage")]
    fn sync_get_node(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        replication_id: &[u8; 32],
        cid: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        if !self.sync_serve_allowed(caller_peer_id.as_ref(), &slot.name) {
            return None;
        }
        crate::commit::read_dag_node(&slot.db, cid).ok().flatten()
    }

    fn manifest(&self) -> Option<crate::network::ManifestReply> {
        self.manifest.get().cloned()
    }

    fn get_proof_blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Hot cache first; disk fallback lazy-hydrates so a peer
        // that put the blob in a previous process incarnation can
        // still serve it. Mirrors `VosNode::get_proof_blob`.
        if let Some(bytes) = self.proof_blobs.read().ok()?.get(hash).cloned() {
            return Some(bytes);
        }
        let dir = self.proof_blobs_dir.as_ref()?;
        let bytes = std::fs::read(dir.join(proof_blob_filename(hash))).ok()?;
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(*hash, bytes.clone());
        }
        Some(bytes)
    }

    fn get_program_blob(&self, peer: Option<libp2p::PeerId>, hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Program code is a space asset even though it is not confidential:
        // require membership, then prove this space catalogs the requested
        // hash before touching the cross-space host cache. The network layer
        // additionally caps per-peer volume; the fetcher re-hashes the reply.
        let peer = peer?;
        if self.lookup_caller_role(Some(&peer)) < AUTH_ROLE_READONLY
            && !self.caller_is_enrolled_node(&peer)
        {
            return None;
        }
        if !self.program_hash_authorized(hash) {
            return None;
        }
        let dir = self.program_blobs_dir.as_ref()?;
        std::fs::read(dir.join(proof_blob_filename(hash))).ok()
    }

    #[cfg(feature = "storage")]
    fn store_private_ingress(
        &self,
        peer: libp2p::PeerId,
        replication_id: &[u8; 32],
        invocation: &[u8; 32],
        content_hash: &[u8; 32],
        content_len: u64,
        bytes: Vec<u8>,
    ) -> bool {
        if bytes.is_empty()
            || bytes.len() > crate::service::ACTOR_PRIVATE_INPUT_MAX_BYTES
            || content_len != bytes.len() as u64
        {
            return false;
        }
        let Some((status, local_prefix)) = self.shared_network.lock().ok().and_then(|network| {
            let network = network.as_ref()?;
            Some((
                network.local_raft_status_cached(replication_id)?,
                network.local_prefix(),
            ))
        }) else {
            return false;
        };
        let prefix = crate::network::derive_node_prefix(&peer);
        if !status.present
            || status.leader_hint != Some(prefix)
            || !status.is_active_voter(prefix)
            || !status.is_active_voter(local_prefix)
        {
            return false;
        }
        let Some(member) = self.lookup_node_member(prefix) else {
            return false;
        };
        if authenticated_service_raft_leader_peer(&status, &member, prefix) != Some(peer) {
            return false;
        }
        let reference = crate::service::BlobRef {
            hash: crate::service::Hash(*content_hash),
            len: content_len,
        };
        if !reference.matches(&bytes) {
            return false;
        }
        let Some(tx) = self
            .service_private_ingress_routes
            .read()
            .ok()
            .and_then(|routes| routes.get(replication_id).map(|route| route.tx.clone()))
        else {
            return false;
        };
        stage_service_private_ingress_through_root(
            &tx,
            crate::service::InvocationId(*invocation),
            reference,
            bytes,
            SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT,
        )
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn raft_voter_peer(&self, replication_id: &[u8; 32], prefix: u16) -> Option<libp2p::PeerId> {
        let status = self
            .shared_network
            .lock()
            .ok()
            .and_then(|network| network.as_ref()?.local_raft_status_cached(replication_id))?;
        if !status.present || !status.is_active_voter(prefix) {
            return None;
        }
        let member = self.lookup_node_member(prefix)?;
        let peer = libp2p::PeerId::from_bytes(&member.key).ok()?;
        node_member_authenticates_active_slot(&member, prefix, &peer).then_some(peer)
    }

    /// Admit a Raft joiner only if it is enrolled as a `NODE_ROLE_VOTER`
    /// in the local space-registry. Fails **closed** — an unreachable or
    /// empty registry reply (`lookup_node_role` → `0` = "not enrolled")
    /// denies the join — so a peer an admin never enrolled cannot make
    /// itself a voter.
    fn raft_join_authorized(&self, prefix: u16) -> bool {
        self.lookup_node_role(prefix) == NODE_ROLE_REPLY_VOTER
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn handle_raft_join(
        &self,
        peer: libp2p::PeerId,
        replication_id: &[u8; 32],
        joiner_prefix: u16,
        production_trust_policy: Option<[u8; 32]>,
        handler: &dyn crate::network::RaftRpcHandler,
    ) -> crate::network::RaftJoinResult {
        let Some(member) = self.lookup_node_member(joiner_prefix) else {
            return crate::network::RaftJoinResult::NotAuthorized;
        };
        if !node_member_authenticates_voter(&member, joiner_prefix, &peer) {
            return crate::network::RaftJoinResult::NotAuthorized;
        }
        let bound = self
            .shared_network
            .lock()
            .ok()
            .and_then(|network| network.clone())
            .is_some_and(|network| {
                network.bind_raft_voter_peer(*replication_id, joiner_prefix, peer)
            });
        if !bound {
            return crate::network::RaftJoinResult::NotAuthorized;
        }
        let route = self
            .service_private_ingress_routes
            .read()
            .ok()
            .and_then(|routes| routes.get(replication_id).cloned());
        let Some(route) = route else {
            // Conformance groups retain their existing join contract.
            return if production_trust_policy.is_none() {
                handler.handle_join(replication_id, joiner_prefix)
            } else {
                crate::network::RaftJoinResult::PolicyMismatch
            };
        };
        if route.production_trust_policy != production_trust_policy {
            return crate::network::RaftJoinResult::PolicyMismatch;
        }
        let Some(_barrier) = route.barrier.try_acquire() else {
            return crate::network::RaftJoinResult::Busy;
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        if route.quiescence_tx.try_send(reply_tx).is_err()
            || reply_rx
                .recv_timeout(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT)
                .ok()
                != Some(true)
        {
            return crate::network::RaftJoinResult::Busy;
        }
        // The guard remains held through `change_membership`: no private
        // admission can race between the quiescence observation and the
        // joint-configuration proposal.
        handler.handle_join(replication_id, joiner_prefix)
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn handle_raft_replace_voter(
        &self,
        caller: libp2p::PeerId,
        operator_peer: libp2p::PeerId,
        replication_id: &[u8; 32],
        old_prefix: u16,
        old_peer: libp2p::PeerId,
        replacement_prefix: u16,
        replacement_peer: libp2p::PeerId,
        operation_epoch: u64,
        operator_signature: [u8; 64],
        handler: &dyn crate::network::RaftRpcHandler,
    ) -> crate::network::RaftReplaceVoterResult {
        use crate::network::RaftReplaceVoterResult;

        let Some(status) = handler.local_status() else {
            return RaftReplaceVoterResult::UnknownGroup;
        };
        let caller_prefix = crate::network::derive_node_prefix(&caller);
        let caller_is_voter = status.is_active_voter(caller_prefix)
            && self
                .lookup_node_member(caller_prefix)
                .is_some_and(|member| {
                    node_member_authenticates_active_slot(&member, caller_prefix, &caller)
                });
        // The first hop is self-authenticated by Noise. A later hop may carry
        // a distinct operator only when the forwarding caller is an exact
        // current voter of this group.
        if caller != operator_peer && !caller_is_voter {
            return RaftReplaceVoterResult::NotAuthorized;
        }
        let Some(space_id) = self.registry_space_id() else {
            return RaftReplaceVoterResult::NotAuthorized;
        };
        if !verifies_raft_voter_replacement_operator(
            &operator_peer,
            &space_id,
            replication_id,
            old_prefix,
            &old_peer,
            replacement_prefix,
            &replacement_peer,
            operation_epoch,
            &operator_signature,
        ) {
            return RaftReplaceVoterResult::NotAuthorized;
        }
        if self.lookup_caller_role(Some(&operator_peer)) < AUTH_ROLE_ADMIN {
            return RaftReplaceVoterResult::NotAuthorized;
        }
        if crate::network::derive_node_prefix(&old_peer) != old_prefix
            || crate::network::derive_node_prefix(&replacement_peer) != replacement_prefix
        {
            return RaftReplaceVoterResult::IdentityMismatch;
        }
        let old_matches = self.lookup_node_member(old_prefix).is_some_and(|member| {
            node_member_authenticates_active_slot(&member, old_prefix, &old_peer)
        });
        let replacement_matches =
            self.lookup_node_member(replacement_prefix)
                .is_some_and(|member| {
                    node_member_authenticates_voter(&member, replacement_prefix, &replacement_peer)
                });
        if !old_matches || !replacement_matches {
            return RaftReplaceVoterResult::IdentityMismatch;
        }
        // A fresh replacement begins only against the exact committed steady
        // configuration the operator observed and signed. Once that exact
        // transition is joint or complete, the same signature remains valid
        // for idempotent polling. Re-enrolling the old voter creates a newer
        // configuration index and invalidates the historical authorization.
        if status.joint_old.is_none()
            && status.members.contains(&old_prefix)
            && status.active_config_index != Some(operation_epoch)
        {
            return RaftReplaceVoterResult::NotAuthorized;
        }

        let proxy_once = |leader_prefix: u16| {
            // A proxied request never proxies again. This bounds leadership
            // churn to one exact-peer hop; the operator can safely retry the
            // idempotent request through its connected daemon.
            if caller != operator_peer {
                return None;
            }
            let network = self
                .shared_network
                .lock()
                .ok()
                .and_then(|network| network.clone())?;
            let leader = self.raft_voter_peer(replication_id, leader_prefix)?;
            let reply = network.send_raft_replace_voter_req(
                leader,
                *replication_id,
                old_prefix,
                old_peer.to_bytes(),
                replacement_prefix,
                replacement_peer.to_bytes(),
                operator_peer.to_bytes(),
                operation_epoch,
                operator_signature,
            );
            reply
                .recv_timeout(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT)
                .ok()
        };

        // Let the leader make the replacement-readiness observation. A
        // follower may have a healthy exact route to its leader without a
        // direct connection to the newly promoted replacement.
        if status.role != crate::network::RaftRole::Leader {
            return status.leader_hint.and_then(proxy_once).unwrap_or(
                RaftReplaceVoterResult::NotLeader {
                    leader_hint: status.leader_hint,
                },
            );
        }

        // Membership replication alone is not enough for a production
        // replacement: the new machine must have applied at least the final
        // configuration that admitted it before an old application replica is
        // retired. Query the exact replacement PeerId, never the prefix map.
        let replacement_status = self
            .shared_network
            .lock()
            .ok()
            .and_then(|network| network.clone())
            .and_then(|network| {
                if network.peer_id() == replacement_peer {
                    network.local_raft_status_cached(replication_id)
                } else {
                    network
                        .send_raft_status_req(replacement_peer, *replication_id)
                        .recv_timeout(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT)
                        .ok()
                }
            });
        let replacement_ready = replacement_status.is_some_and(|status| {
            status.present
                && status.members.contains(&replacement_prefix)
                && status.joint_old.is_none()
                && status.active_config_index.is_some_and(|index| {
                    index <= status.commit_index && index <= status.last_applied
                })
        });
        if !replacement_ready {
            return RaftReplaceVoterResult::ReplacementNotReady;
        }

        let route = self
            .service_private_ingress_routes
            .read()
            .ok()
            .and_then(|routes| routes.get(replication_id).cloned());
        let Some(route) = route else {
            // This production surface is intentionally limited to service roots;
            // other groups have no durable private-input quiescence contract.
            return RaftReplaceVoterResult::UnknownGroup;
        };
        let Some(barrier) = route.barrier.try_acquire() else {
            return RaftReplaceVoterResult::Busy;
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        if route.quiescence_tx.try_send(reply_tx).is_err()
            || reply_rx
                .recv_timeout(SERVICE_PRIVATE_INGRESS_STAGE_TIMEOUT)
                .ok()
                != Some(true)
        {
            return RaftReplaceVoterResult::Busy;
        }
        let result = handler.handle_replace_voter(replication_id, old_prefix, replacement_prefix);
        drop(barrier);
        match result {
            RaftReplaceVoterResult::NotLeader {
                leader_hint: Some(leader),
            } => proxy_once(leader).unwrap_or(RaftReplaceVoterResult::NotLeader {
                leader_hint: Some(leader),
            }),
            other => other,
        }
    }
}

/// Replay every log in the strategy's DAG against `runtime`'s
/// state for `svc_id`. Used by both cold-start recovery and
/// mid-flight soft restarts after the sync ticker merges new
/// nodes. Caller is responsible for clearing prior state when
/// rebuilding from scratch — this function only feeds messages
/// through `begin_replay` and lets the actor produce state.
fn replay_dag_into_runtime(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    let logs = validated_replay_logs(svc_id, strategy)?;
    replay_logs_into_runtime(runtime, svc_id, strategy, logs)
}

/// One argument kind in the space-registry's dynamic inbound request surface.
///
/// This is deliberately the same vocabulary used by the `#[messages]`
/// generated dynamic decoder. Numeric kinds accept the lossless widening and
/// narrowing conversions implemented by [`crate::value::Value`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryReplayArgKind {
    /// A `bool` argument.
    Bool,
    /// A losslessly representable `u8` argument.
    U8,
    /// A losslessly representable `u32` argument.
    U32,
    /// A losslessly representable `u64` argument.
    U64,
    /// A `String` argument.
    String,
    /// A `Vec<u8>` argument.
    Bytes,
}

impl RegistryReplayArgKind {
    /// Canonical type spelling emitted into actor metadata by `#[messages]`.
    pub const fn metadata_type(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::U8 => "u8",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::String => "String",
            Self::Bytes => "Vec<u8>",
        }
    }

    fn accepts(self, value: &crate::value::Value) -> bool {
        match self {
            Self::Bool => value.as_bool().is_some(),
            Self::U8 => value.as_u8().is_some(),
            Self::U32 => value.as_u32().is_some(),
            Self::U64 => value.as_u64().is_some(),
            Self::String => value.as_str().is_some(),
            Self::Bytes => value.as_bytes().is_some(),
        }
    }
}

/// Exact dynamic request shape accepted into a registry replay history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryReplayMethod {
    /// Dynamic method name.
    pub name: &'static str,
    /// Required named arguments. Every field must occur exactly once and no
    /// unrecognized field is accepted; field order remains semantically free.
    pub fields: &'static [(&'static str, RegistryReplayArgKind)],
}

use RegistryReplayArgKind::{Bool, Bytes, String as RegistryString, U8, U32, U64};

/// Complete allowlist of the current space-registry's inbound methods.
///
/// A `vosx` cross-crate test compares this table to the actor macro's emitted
/// metadata, including every field name and type. Keeping the table here lets
/// peer admission and cold/mid-flight replay use one predicate without making
/// the foundational `vos` crate depend on the registry actor crate.
pub const REGISTRY_REPLAY_METHODS: &[RegistryReplayMethod] = &[
    RegistryReplayMethod {
        name: "set_root",
        fields: &[
            ("root", Bytes),
            ("schema_version", U32),
            ("schema_hash", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "protocol",
        fields: &[],
    },
    RegistryReplayMethod {
        name: "root",
        fields: &[],
    },
    RegistryReplayMethod {
        name: "set_space_id",
        fields: &[("space_id", Bytes)],
    },
    RegistryReplayMethod {
        name: "space_id",
        fields: &[],
    },
    RegistryReplayMethod {
        name: "role_authority",
        fields: &[],
    },
    RegistryReplayMethod {
        name: "set_role_authority",
        fields: &[("authority_replication_id", Bytes), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "publish_service_program",
        fields: &[
            ("name", RegistryString),
            ("hash", Bytes),
            ("crdt", Bool),
            ("publication_id", Bytes),
            ("expected_publication_id", Bytes),
            ("expected_hash", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "publish_agent_actor_program",
        fields: &[
            ("name", RegistryString),
            ("hash", Bytes),
            ("publication_id", Bytes),
            ("expected_publication_id", Bytes),
            ("expected_hash", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "unpublish_service_program",
        fields: &[
            ("name", RegistryString),
            ("expected_publication_id", Bytes),
            ("expected_hash", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "unpublish_agent_actor_program",
        fields: &[
            ("name", RegistryString),
            ("expected_publication_id", Bytes),
            ("expected_hash", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "catalog_program",
        fields: &[("name", RegistryString)],
    },
    RegistryReplayMethod {
        name: "catalog_program_by_hash",
        fields: &[("hash", Bytes)],
    },
    RegistryReplayMethod {
        name: "program_blob_authorized",
        fields: &[("hash", Bytes)],
    },
    RegistryReplayMethod {
        name: "catalog_programs",
        fields: &[("after_name", RegistryString), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "register_meta",
        fields: &[("program_hash", Bytes), ("blob", Bytes), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "meta_for_program",
        fields: &[("program_hash", Bytes)],
    },
    RegistryReplayMethod {
        name: "meta_for_instance",
        fields: &[("name", RegistryString)],
    },
    RegistryReplayMethod {
        name: "register_extension_meta",
        fields: &[
            ("instance_name", RegistryString),
            ("blob", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "install_service_actor",
        fields: &[
            ("instance_name", RegistryString),
            ("program_name", RegistryString),
            ("program_hash", Bytes),
            ("program_publication_id", Bytes),
            ("installation_id", Bytes),
            ("replication_id", Bytes),
            ("consistency", U8),
            ("network_reachable", Bool),
            ("sync_role", U8),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "install_system_actor",
        fields: &[("receipt", Bytes), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "uninstall_service_actor",
        fields: &[
            ("instance_name", RegistryString),
            ("installation_id", Bytes),
            ("expected_revision", U64),
            ("expected_program_hash", Bytes),
            ("expected_program_publication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "uninstall_system_actor",
        fields: &[
            ("instance_name", RegistryString),
            ("installation_id", Bytes),
            ("expected_revision", U64),
            ("expected_program_hash", Bytes),
            ("expected_program_publication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "upgrade_service_actor",
        fields: &[
            ("instance_name", RegistryString),
            ("installation_id", Bytes),
            ("expected_revision", U64),
            ("from_program_hash", Bytes),
            ("from_program_publication_id", Bytes),
            ("new_program_name", RegistryString),
            ("new_program_hash", Bytes),
            ("new_program_publication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "upgrade_system_actor",
        fields: &[
            ("instance_name", RegistryString),
            ("installation_id", Bytes),
            ("expected_revision", U64),
            ("from_program_hash", Bytes),
            ("from_program_publication_id", Bytes),
            ("new_program_name", RegistryString),
            ("new_program_hash", Bytes),
            ("new_program_publication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "service_actor",
        fields: &[("instance_name", RegistryString)],
    },
    RegistryReplayMethod {
        name: "service_actor_by_pattern",
        fields: &[("prefix", RegistryString), ("suffix", RegistryString)],
    },
    RegistryReplayMethod {
        name: "service_actors",
        fields: &[("after_name", RegistryString), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "system_actor",
        fields: &[("instance_name", RegistryString)],
    },
    RegistryReplayMethod {
        name: "system_actors",
        fields: &[("after_name", RegistryString), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "service_actor_names",
        fields: &[("after_name", RegistryString), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "resolve",
        fields: &[("name", RegistryString), ("caller_prefix", U64)],
    },
    RegistryReplayMethod {
        name: "register_remote",
        fields: &[
            ("instance_name", RegistryString),
            ("host_prefix", U32),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "host_mappings",
        fields: &[("after_name", RegistryString), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "add_node",
        fields: &[
            ("prefix", U32),
            ("peer_id", Bytes),
            ("role", U8),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "remove_node",
        fields: &[("prefix", U32), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "add_identity",
        fields: &[
            ("public_key", Bytes),
            ("proof_kind", U8),
            ("proof_data", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "remove_identity",
        fields: &[("public_key", Bytes), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "members",
        fields: &[("after_kind", U8), ("after_key", Bytes), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "node_role",
        fields: &[("prefix", U64)],
    },
    RegistryReplayMethod {
        name: "grant_role",
        fields: &[
            ("peer_id", Bytes),
            ("role", U8),
            ("epoch", U64),
            ("authority_replication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "revoke_role",
        fields: &[
            ("peer_id", Bytes),
            ("epoch", U64),
            ("authority_replication_id", Bytes),
            ("auth", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "peer_role",
        fields: &[("peer_id", Bytes)],
    },
    RegistryReplayMethod {
        name: "peer_epoch",
        fields: &[("peer_id", Bytes)],
    },
    RegistryReplayMethod {
        name: "auth_grants",
        fields: &[("after_peer", Bytes), ("budget", U32)],
    },
    RegistryReplayMethod {
        name: "redeem_invite",
        fields: &[
            ("token_pub", Bytes),
            ("role", U8),
            ("expires_at", U64),
            ("authority_replication_id", Bytes),
            ("admin_peer_id", Bytes),
            ("admin_sig", Bytes),
            ("peer_id", Bytes),
            ("redeem_sig", Bytes),
            ("node_sig", Bytes),
            ("authority_attestation", Bytes),
        ],
    },
    RegistryReplayMethod {
        name: "revoke_invite",
        fields: &[("token_pub", Bytes), ("auth", Bytes)],
    },
    RegistryReplayMethod {
        name: "invites",
        fields: &[("after", Bytes), ("budget", U32)],
    },
];

fn registry_replay_message_has_exact_shape(message: &crate::value::Msg) -> bool {
    let Some(method) = REGISTRY_REPLAY_METHODS
        .iter()
        .find(|method| method.name == message.name)
    else {
        return false;
    };
    if message.args.0.len() != method.fields.len() {
        return false;
    }
    method.fields.iter().all(|(expected_name, kind)| {
        let mut matches = message
            .args
            .0
            .iter()
            .filter(|(actual_name, value)| actual_name == expected_name && kind.accepts(value));
        matches.next().is_some() && matches.next().is_none()
    })
}

/// Decode and validate one effect log that may enter registry replay.
///
/// Empty messages are the host's on-start kick and are the sole non-dynamic
/// exception. Every other message must be the canonical checked encoding of a
/// current, exactly shaped registry request. The registry actor has no
/// `Context::ask`/child-invoke entrypoint, so reply transcripts and folded
/// invoke effects cannot have been produced by a legitimate registry dispatch;
/// admitting them would make replay leave entries unconsumed and fail-stop.
/// Host-recorded caller, invocation, and work-result anchor fields remain
/// accepted because those are legitimate effects of dispatch recording.
pub fn registry_replay_request(
    log: &crate::effect_log::EffectLog,
) -> Result<Option<crate::value::Msg>, &'static str> {
    if !log.replies.is_empty() || !log.invoke_effects.is_empty() {
        return Err("registry replay contains an impossible reply/result transcript");
    }
    if log.msg.is_empty() {
        return Ok(None);
    }
    if log.msg.first() != Some(&crate::value::TAG_DYNAMIC) {
        return Err("registry replay contains a non-dynamic application message");
    }
    let Some(message) = <crate::value::Msg as crate::Decode>::try_decode(&log.msg[1..]) else {
        return Err("registry replay contains a malformed dynamic message");
    };
    if crate::Encode::encode(&message).as_slice() != &log.msg[1..] {
        return Err("registry replay contains a non-canonical dynamic message");
    }
    if !registry_replay_message_has_exact_shape(&message) {
        return Err("registry replay contains an unknown or malformed registry request");
    }
    Ok(Some(message))
}

/// Decode a complete peer DAG node and apply [`registry_replay_request`] to
/// its event log. This is the live-ingress half of the shared registry replay
/// boundary; using the typed decoder also makes hostile length fields fail
/// closed without unchecked offset arithmetic.
#[cfg(feature = "storage")]
pub fn registry_replay_node_request(
    node_bytes: &[u8],
) -> Result<Option<crate::value::Msg>, &'static str> {
    let Some(node) =
        merkle_crdt::DagNode::<crate::commit::Blake2b, crate::effect_log::CrdtEvent>::from_bytes(
            node_bytes,
        )
    else {
        return Err("registry peer node uses a malformed or retired DAG wire");
    };
    if node.to_bytes().as_slice() != node_bytes {
        return Err("registry peer node uses a non-canonical DAG wire");
    }
    registry_replay_request(&node.payload.log)
}

/// Load and validate one durable history without changing the strategy's
/// canonical causal order.
///
/// In particular, do not sort role revocations ahead of data mutations. Such
/// a sort makes a mutation which was validly committed before a later revoke
/// disappear on cold replay, while still being unable to distinguish captured
/// signed bytes which were never committed. The clean catalog protocol closes
/// that gap with immutable authority-finalization evidence; CID or method-name
/// ordering is not an authorization proof.
fn validated_replay_logs(
    svc_id: ServiceId,
    strategy: &dyn crate::commit::CommitStrategy,
) -> Result<Vec<crate::effect_log::EffectLog>, String> {
    let logs = strategy
        .replay_logs()
        .map_err(|e| format!("replay_logs failed: {e}"))?;
    if !matches!(
        svc_id.local_id(),
        id if id == ServiceId::REGISTRY.local_id()
            || id == ServiceId::HYPERSPACE_REGISTRY.local_id()
    ) {
        return Ok(logs);
    }

    let mut saw_root = false;
    let mut saw_current_root = false;
    for log in &logs {
        let Some(message) = registry_replay_request(log).map_err(str::to_owned)? else {
            continue;
        };
        if message.name == "set_root" {
            if saw_root {
                return Err("registry replay contains more than one genesis-root operation".into());
            }
            saw_root = true;
            saw_current_root = message.args.get_u32("schema_version")
                == Some(crate::registry::REGISTRY_SCHEMA_VERSION)
                && message.args.get_bytes("schema_hash").as_deref()
                    == Some(crate::registry::REGISTRY_SCHEMA_HASH.as_slice())
                && message
                    .args
                    .get_bytes("root")
                    .is_some_and(|root| !root.is_empty());
        }
    }
    if saw_root && !saw_current_root {
        return Err(
            "registry replay contains a legacy or schema-incompatible genesis-root operation"
                .into(),
        );
    }

    Ok(logs)
}
fn replay_logs_into_runtime(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &dyn crate::commit::CommitStrategy,
    logs: Vec<crate::effect_log::EffectLog>,
) -> Result<(), String> {
    if logs.is_empty() {
        return Ok(());
    }
    for (i, log) in logs.into_iter().enumerate() {
        let msg = log.msg.clone();
        // The (kind, anchor) recorded in this durable log node — the
        // state the ORIGINAL dispatch ran against. The replayed
        // dispatch must re-emit the same anchor, or the rebuilt state
        // history has diverged. This is the normative divergence check:
        // the guest's own anchor self-check passes by construction
        // during replay (it anchors whatever the runtime just served
        // it) and detects nothing.
        let recorded_anchor = (log.anchor_kind, log.anchor);
        let recorded_caller = log.caller_prefix;
        let recorded_invocation = log.invocation_id();
        let _ = runtime.take_dispatch_anchor(svc_id);
        // Replayed dispatches populate the same per-dispatch delta
        // trackers real dispatches do; nothing commits them during
        // replay (the durable history already holds them), so drain
        // them — leaking a replayed dispatch's effect-bearing marker
        // into the next real dispatch would make a pure read on a Raft
        // follower propose (and fail NotLeader, dropping its reply).
        let _ = runtime.take_dispatch_delta(svc_id);
        runtime.begin_replay(log);
        // An empty-msg node is a recorded kick dispatch — the
        // host-synthesized wake-up whose whole semantic is "run
        // on_start". Replay it as exactly that: a raw empty payload
        // (never prefix-wrapped — the actor would strip the prefix
        // back to empty bytes and panic decoding them as a message;
        // the runtime instead filters the empty item and the guest
        // runs its cold-start path with no mail). Skipping these
        // nodes instead would drop on_start's state transition and
        // break the anchor chain for every node after.
        //
        // Non-empty dispatches replay under the RECORDED caller
        // prefix — the original caller's trust flag and role grants —
        // so every gate decision reproduces exactly: a role-refused
        // dispatch replays as refused (its durable node may still
        // carry framework effects like the genesis state write), a
        // granted one as granted. Logs without a recorded
        // prefix decode as trusted-System, their historical replay
        // identity.
        if msg.is_empty() {
            runtime.send_to(svc_id, Vec::new());
        } else {
            runtime.send_to(
                svc_id,
                encode_replay_payload(&recorded_caller, recorded_invocation, &msg),
            );
        }
        runtime.run_blocking();
        // External transfers emitted during replay had their
        // original effects at record time; we don't re-issue them.
        let _ = runtime.drain_external_transfers(svc_id);
        let replay = runtime.finish_replay().expect("replay was active");
        if !replay.is_complete() {
            return Err(format!(
                "replay diverged at log #{i} (pos={}, exhausted={}); \
                 handler is non-deterministic",
                replay.position(),
                replay.was_exhausted(),
            ));
        }
        let replayed_anchor = runtime.take_dispatch_anchor(svc_id);
        let _ = runtime.take_dispatch_delta(svc_id);
        if recorded_anchor.0 != crate::effect_log::ANCHOR_UNRECORDED
            && replayed_anchor != Some(recorded_anchor)
        {
            if strategy.linear_history() {
                return Err(format!(
                    "replay diverged at log #{i}: re-emitted work-result anchor \
                     {replayed_anchor:02x?} != recorded {recorded_anchor:02x?} — \
                     rebuilt state history differs from the committed one",
                ));
            }
            // Merged-DAG replay serializes concurrent branches into an
            // order their recorded anchors never observed — expected,
            // not divergence. Kept observable for diagnostics.
            debug!(
                %svc_id,
                log = i,
                ?replayed_anchor,
                ?recorded_anchor,
                "replayed anchor differs from recorded (merged-DAG serialization)",
            );
        }
    }
    Ok(())
}

/// Soft restart for a CRDT actor. Picks up whatever the sync
/// ticker merged into our redb file, throws away the locally-
/// derived runtime state, replays every log in the merged DAG,
/// and commits the rebuilt state plus the whole rebuilt keyspace
/// (see [`rebuilt_rows`] — merged remote dispatches' rows exist
/// nowhere else). Idempotent — calling it twice in a row produces
/// the same final state.
///
/// Called from the agent thread between dispatches when the
/// sync notifier fires, so blocking is fine. Returns `Err(msg)`
/// only on host-side errors (corrupt strategy, non-deterministic
/// handler) — caller logs and tears the agent down.
///
/// Only the sync-driven CRDT/Raft restart path calls this, and that
/// path needs the network (the sync notifier rides libp2p), so it's
/// gated `all(storage, network)` to match its callers — otherwise it's
/// dead code in a storage-only build.
#[cfg(all(feature = "storage", feature = "network"))]
fn soft_restart_crdt(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &mut dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    strategy
        .reload()
        .map_err(|e| format!("strategy.reload: {e}"))?;
    // Validate and order the complete merged history before clearing a live
    // keyspace. A stale-generation registry must remain diagnostically
    // readable on disk; discovering it only after `clear_service` would turn
    // a clean-break refusal into data loss.
    let logs = validated_replay_logs(svc_id, strategy)?;
    // Replay rebuilds every row by re-executing the guest from genesis,
    // so it must run against the empty slate a cold-boot replay sees —
    // not just a STATE_KEY-less one. The storage-type meta/index and
    // `StorageVec` length rows are accumulators: replaying inserts/pushes
    // onto the live pre-merge rows rebuilds a divergent physical layout
    // (and doubles a `StorageVec`'s length), which the state anchor does
    // not cover, so two replicas would silently stop being row-identical.
    // Wipe the whole keyspace and restore only INIT_KEY — the host-seeded
    // constructor input the genesis dispatch legitimately reads, which
    // replay never re-emits.
    let init = runtime
        .storage
        .read(svc_id, crate::lifecycle::INIT_KEY)
        .map(|v| v.to_vec());
    runtime.storage.clear_service(svc_id);
    if let Some(init) = init {
        runtime
            .storage
            .write(svc_id, crate::lifecycle::INIT_KEY, &init);
    }
    replay_logs_into_runtime(runtime, svc_id, strategy, logs)?;
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    if !state.is_empty() {
        // The soft-restart slate was seeded with INIT_KEY alone (above).
        let rows = rebuilt_rows(runtime, svc_id, &[crate::lifecycle::INIT_KEY]);
        strategy
            .commit_rebuilt(&state, &rows)
            .map_err(|e| format!("post-soft-restart commit: {e}"))?;
    }
    Ok(())
}

/// The rebuilt keyspace a replay left in the runtime, ready for
/// [`CommitStrategy::commit_rebuilt`]: every row except STATE_KEY
/// (which travels separately as the state blob), the continuation
/// header (host bookkeeping written outside dispatch deltas by
/// design — a replica applying the same history incrementally never
/// persists it, so persisting it here would break cross-replica
/// byte-parity and re-seed a dangling header whose kernel-snapshot body is
/// gone), and `host_seeded` keys (rows the host writes from the
/// manifest on every spawn, INIT_KEY at minimum — persisting one
/// would let a stale copy shadow a manifest edit on the next boot).
///
/// Local dispatch deltas persist rows incrementally, but the rows a
/// replay produces for *merged remote* dispatches exist only here in
/// the runtime — without persisting the full slate, a cold reopen
/// (`restore_writes`) comes back missing every remotely-replicated
/// row, and a later local delta can persist index pages that name
/// value rows the table doesn't hold.
fn rebuilt_rows(
    runtime: &VosRuntime,
    svc_id: ServiceId,
    host_seeded: &[&[u8]],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    runtime
        .storage
        .scan_prefix(svc_id, b"")
        .filter(|(key, _)| {
            *key != crate::lifecycle::STATE_KEY_BYTES
                && *key != crate::lifecycle::CONTINUATION_HEADER_KEY
                && !host_seeded.contains(key)
        })
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect()
}

/// How often the per-replica sync ticker fires. Short enough that
/// integration tests can observe convergence in a few hundred ms,
/// long enough that idle clusters don't flood the wire.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_INTERVAL: Duration = Duration::from_millis(250);

/// Per-fetch deadline. Peers that disappear mid-handshake still
/// only steal this long from the ticker.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Every Nth sync tick we re-probe all connected peers (not
/// just known group members) so newly-joined replicas of an
/// existing group get discovered. Picked to be a small
/// multiple of the tick interval — at 250ms × 8, that's a 2s
/// upper bound on discovering a new peer for a group we
/// already track.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_REPROBE_EVERY: u64 = 8;

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug)]
enum SyncOutcome {
    /// Peer has the replication group. `inserted` is true iff
    /// at least one DAG node was new locally.
    PeerHasGroup { inserted: bool },
    /// Peer answered with empty heads — they don't (currently)
    /// host this group. Treated as a soft signal: the membership
    /// cache demotes them, but a full re-probe sweep
    /// (`SYNC_REPROBE_EVERY` ticks later) gives them another shot.
    PeerEmpty,
}

/// Background ticker for one replication group. Tracks which
/// connected peers have actually answered with non-empty heads
/// for this group and only fans the BFS pull out to those —
/// otherwise an N-peer / M-group cluster eats N×M FetchHeads
/// frames per tick. Every [`SYNC_REPROBE_EVERY`] ticks the
/// loop also probes peers it doesn't yet have membership info
/// for, picking up replicas that joined the group after the
/// initial discovery sweep.
///
/// Runs detached — exits when `shutdown` is set or every clone
/// of the relevant `Arc`s has been dropped (signalling the
/// network/node/db they reference is gone). When `notifier` is
/// `Some`, sends `()` after every cycle that brought in at
/// least one new node so the agent thread can soft-restart and
/// pick up the merged state.
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_loop(
    rep_id: [u8; 32],
    shared_network: SharedNetwork,
    slot: ReplicaSlot,
    shutdown: Arc<AtomicBool>,
    notifier: Option<mpsc::Sender<()>>,
) {
    let mut confirmed: HashSet<libp2p::PeerId> = HashSet::new();
    let mut tick: u64 = 0;
    let mut subscribed = false;
    let (hint_tx, hint_rx) = mpsc::channel::<libp2p::PeerId>();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SYNC_INTERVAL);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
            continue;
        };
        // First time we see the network attached, subscribe to
        // the gossipsub topic and register our hint channel so
        // peer head announcements wake us up.
        if !subscribed {
            net.join_replication(rep_id, hint_tx.clone());
            subscribed = true;
        }
        let local = net.peer_id();
        let connected: HashSet<libp2p::PeerId> = net
            .connected_peers()
            .into_iter()
            .filter(|p| p != &local)
            .collect();
        // Drop peers that disconnected since our last tick.
        confirmed.retain(|p| connected.contains(p));

        // Drain pending gossipsub hints — peers that just
        // published heads. Each hint triggers an immediate
        // (single-peer) sync, bypassing the periodic poll.
        let mut hinted: Vec<libp2p::PeerId> = Vec::new();
        while let Ok(peer) = hint_rx.try_recv() {
            if peer != local && connected.contains(&peer) && !hinted.contains(&peer) {
                hinted.push(peer);
            }
        }

        // Reprobe sweep: every Nth tick (or whenever we have no
        // confirmed members yet) hit every connected peer to
        // find new group hosts. Otherwise stick to the cache
        // plus any hinted peers from the gossipsub side.
        let reprobe = tick.is_multiple_of(SYNC_REPROBE_EVERY) || confirmed.is_empty();
        tick = tick.wrapping_add(1);

        let mut targets: Vec<libp2p::PeerId> = if reprobe {
            connected.iter().copied().collect()
        } else {
            confirmed.iter().copied().collect()
        };
        for h in &hinted {
            if !targets.contains(h) {
                targets.push(*h);
            }
        }

        let mut any_inserted = false;
        for peer in targets {
            match sync_with_peer(&net, peer, &rep_id, &slot) {
                Ok(SyncOutcome::PeerHasGroup { inserted }) => {
                    confirmed.insert(peer);
                    if inserted {
                        any_inserted = true;
                    }
                }
                Ok(SyncOutcome::PeerEmpty) => {
                    // Demote — they're either out of the group
                    // or briefly empty during their own cold
                    // start. The next reprobe rediscovers them.
                    confirmed.remove(&peer);
                }
                Err(e) => warn!(error = %e, "sync: per-peer cycle failed"),
            }
        }
        if any_inserted && let Some(n) = &notifier {
            let _ = n.send(());
        }
    }
}

/// One pull cycle against a single peer for one replication
/// group. Returns:
///   - `PeerHasGroup { inserted }` when the peer answered with
///     non-empty heads (regardless of whether anything new was
///     pulled in)
///   - `PeerEmpty` when the peer reports no heads — interpreted
///     as "this peer doesn't host the group right now"
///
/// Errors only on host-side commit failures; transient network
/// failures surface as a timeout / disconnect, which we silently
/// treat as `PeerEmpty` for the membership cache (the next
/// reprobe sweep retries).
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_with_peer(
    net: &crate::network::Network,
    peer: libp2p::PeerId,
    rep_id: &[u8; 32],
    slot: &ReplicaSlot,
) -> Result<SyncOutcome, crate::commit::CommitError> {
    use crate::commit::CrdtCommit;
    use crate::effect_log::CrdtEvent;
    use merkle_crdt::DagNode;

    let heads_rx = net.send_fetch_heads(peer, *rep_id);
    let heads = match heads_rx.recv_timeout(SYNC_FETCH_TIMEOUT) {
        Ok(v) => v,
        Err(_) => return Ok(SyncOutcome::PeerEmpty),
    };
    if heads.is_empty() {
        return Ok(SyncOutcome::PeerEmpty);
    }

    // Sync only inserts peer-produced DAG nodes; it never allocates
    // a fresh `(origin, seq)`. The replica_origin we hand the
    // strategy here would only matter if a local write slipped in
    // — derive it the same way the agent thread does so the two
    // CrdtCommits over the same redb agree on origin if they ever
    // both write.
    let replica_origin = derive_replica_origin(rep_id, net.local_prefix());
    let mut cc =
        CrdtCommit::from_db_arc_locked(slot.db.clone(), slot.commit_lock.clone(), replica_origin)?;
    // Gate peer nodes through the replica's validator (the registry binds
    // the genesis set_root to its space_id) — this is the ingest point.
    cc.set_node_validator(slot.node_validator.clone());
    let mut frontier: Vec<[u8; 32]> = heads.clone();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut inserted_any = false;

    while let Some(cid) = frontier.pop() {
        if !seen.insert(cid) {
            continue;
        }
        if cc.get_node_bytes(&cid)?.is_some() {
            continue;
        }
        let node_rx = net.send_fetch_node(peer, *rep_id, cid);
        let Ok(Some(node_bytes)) = node_rx.recv_timeout(SYNC_FETCH_TIMEOUT) else {
            continue;
        };
        match cc.insert_node(&cid, &node_bytes) {
            Ok(true) => inserted_any = true,
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "sync: node from peer rejected");
                continue;
            }
        }
        // Walk children so the BFS keeps going.
        if let Some(node) = DagNode::<crate::commit::Blake2b, CrdtEvent>::from_bytes(&node_bytes) {
            for child in node.children {
                frontier.push(child.0);
            }
        }
    }

    if inserted_any {
        cc.compact_roots()?;
    }
    Ok(SyncOutcome::PeerHasGroup {
        inserted: inserted_any,
    })
}

/// Shared "last activity" instant, bumped on every dispatch. The
/// node uses it as a global idle signal that — unlike outbox-only
/// monitoring — also accounts for invoke traffic, which doesn't
/// flow through the outbox.
type ActivityClock = Arc<Mutex<Instant>>;

impl VosNode {
    /// Create a node with the default prefix (0 = local/unscoped).
    pub fn new() -> Self {
        Self::with_prefix(0)
    }

    /// Create a node with a specific network prefix.
    pub fn with_prefix(node_prefix: u16) -> Self {
        let (outbox_tx, outbox_rx) = mpsc::channel();
        #[cfg(all(feature = "network", feature = "storage"))]
        let (pending_service_root_ready_tx, pending_service_root_ready_rx) = mpsc::channel();
        let mut service_invocation_seed = [0_u8; 32];
        getrandom::getrandom(&mut service_invocation_seed)
            .expect("OS entropy for service host invocation identities");
        Self {
            node_prefix,
            next_local: AtomicU16::new(1), // 0 is reserved for registry
            routes: HashMap::new(),
            agents: Vec::new(),
            outbox_tx,
            outbox_rx,
            invoke_routes: Arc::new(Mutex::new(HashMap::new())),
            service_actor_routes: Arc::new(RwLock::new(HashMap::new())),
            service_invocation_seed,
            service_invocation_ordinal: Arc::new(AtomicU64::new(1)),
            service_logical_timeslot: Arc::new(AtomicU64::new(service_wall_timeslot())),
            agent_names: Arc::new(std::sync::RwLock::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            agent_shutdown: Arc::new(Mutex::new(HashMap::new())),
            agent_info: Arc::new(std::sync::RwLock::new(HashMap::new())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            #[cfg(feature = "network")]
            shared_network: Arc::new(Mutex::new(None)),
            #[cfg(feature = "network")]
            operator_peer: None,
            operator_signer: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            crdt_replicas: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            raft_hosts: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            service_private_ingress_routes: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            service_raft_transport_resolutions: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            service_raft_transport_ownership_generation: AtomicU64::new(0),
            #[cfg(all(feature = "network", feature = "storage"))]
            pending_service_root_ready_tx,
            #[cfg(all(feature = "network", feature = "storage"))]
            pending_service_root_ready_rx,
            #[cfg(all(feature = "network", feature = "storage"))]
            pending_service_root_threads: Vec::new(),
            #[cfg(all(feature = "network", feature = "storage"))]
            pending_service_root_ids: Arc::new(Mutex::new(std::collections::HashSet::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            pending_service_root_actors: Arc::new(Mutex::new(std::collections::HashSet::new())),
            #[cfg(feature = "network")]
            manifest: Arc::new(OnceLock::new()),
            #[cfg(all(feature = "network", feature = "storage"))]
            sync_threads: Vec::new(),
            #[cfg(any(feature = "http-ingress", feature = "ssh-ingress"))]
            ingress_threads: Vec::new(),
            #[cfg(feature = "ssh-ingress")]
            ingress_node_attester: None,
            proof_blobs: Arc::new(RwLock::new(HashMap::new())),
            proof_blobs_dir: None,
            program_blobs_dir: None,
            local_agent_host: None,
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_agent_owner: None,
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_agent_ingress_supervisor: Arc::new(RwLock::new(None)),
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_agent_recovering: Arc::new(AtomicBool::new(false)),
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_local_lifecycle_queue: Arc::new(
                crate::agent::local_lifecycle::LocalLifecycleQueue::default(),
            ),
        }
    }

    /// Enable on-disk persistence for the proof-blob CAS at the
    /// given directory. Blobs `put` after this call write through
    /// to `{dir}/{hex_hash}`; on a hot-cache miss, `get` lazy-loads
    /// from disk before returning `None`. The directory is created
    /// if missing.
    ///
    /// Call this before driving any proof traffic so the disk shape
    /// is consistent across put / get. Re-calling overrides the
    /// previous directory; the in-memory hot cache is unaffected.
    pub fn with_proof_blobs_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        self.proof_blobs_dir = Some(dir);
        self
    }

    /// Point the node at the host's program-blob cache directory so it can
    /// serve actor ELFs to space members over `FetchProgramBlob`. The host
    /// (vosx) passes its content-addressed `blob_store` cache dir, whose
    /// `{dir}/{hex_hash}` layout the node reads by hash. Serving is
    /// membership-gated; the directory itself is never written by `vos`.
    pub fn with_program_blobs_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.program_blobs_dir = Some(dir.into());
        self
    }

    /// Attach the one Agent-native Local image owner for this node.
    ///
    /// This seals only process ownership and lifecycle. It does not publish a
    /// route, mint authority evidence, or project an Agent into a legacy
    /// [`ServiceId`]. A duplicate, stopped, or post-shutdown attachment
    /// returns the incoming control unchanged so its owner can shut it down
    /// explicitly. The node deliberately does not return or expose the raw
    /// command handle after taking ownership.
    pub fn attach_local_agent_host(
        &mut self,
        control: crate::agent::host::AgentHostControl,
    ) -> Result<(), Box<crate::agent::host::AgentHostControl>> {
        if self.local_agent_host.is_some()
            || !control.is_running()
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err(Box::new(control));
        }
        self.local_agent_host = Some(control);
        Ok(())
    }

    /// Consume the live clean system-Agent bootstrap owner and start the one
    /// authenticated production route owner for this node. Initial bounded
    /// reconciliation completes before the supervisor becomes visible to
    /// ingress; all resulting workers are subsequently shut down and joined
    /// by this node.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn start_clean_agent_production<P, R, I>(
        &mut self,
        node: crate::agent::sdk::NodeId,
        system_owner: crate::agent::clean_bootstrap::CleanSystemAgentBootstrapOwner<P, R, I>,
        authenticator: Box<
            dyn crate::agent::production_owner::AuthorityProjectionQueryAuthenticator,
        >,
        supervisor_limits: crate::agent::supervisor::AgentSupervisorLimits,
        route_queue_capacity: usize,
        reconcile_interval: Duration,
    ) -> Result<(), crate::agent::production_owner::AgentProductionOwnerError>
    where
        P: crate::agent::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
        R: crate::agent::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
        I: crate::agent::clean_authority_issuer::CleanManagementIssuerStore + Send + 'static,
    {
        if self.clean_agent_owner.is_some() || self.shutdown.load(Ordering::Acquire) {
            // Dropping the still-exclusive bootstrap owner retires its exact
            // network generations and joins their workers. In particular, a
            // rejected duplicate never starts a projection client or exposes
            // a second supervisor.
            drop(system_owner);
            return Err(crate::agent::production_owner::AgentProductionOwnerError::DuplicateHost);
        }
        let system_attachment =
            crate::agent::supervisor_adapters::system_agent_supervisor_attachment(
                system_owner,
                route_queue_capacity,
            )?;
        let owner = crate::agent::production_owner::AgentProductionOwner::start(
            node,
            supervisor_limits,
            system_attachment,
            authenticator,
            reconcile_interval,
        )?;
        self.attach_clean_agent_owner(owner)
    }

    /// Retain Local lifecycle coordination inside the production owner. Initial
    /// authenticated reconciliation includes the physical Local host before
    /// any supervisor handle is exposed to ingress.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn start_clean_local_agent_production<P, R, I, F, S>(
        &mut self,
        node: crate::agent::sdk::NodeId,
        lifecycle: crate::agent::local_lifecycle::LocalLifecycleController<P, R, I, F, S>,
        authenticator: Box<
            dyn crate::agent::production_owner::AuthorityProjectionQueryAuthenticator,
        >,
        limits: crate::agent::supervisor::AgentSupervisorLimits,
        queue_capacity: usize,
        reconcile_interval: Duration,
    ) -> Result<(), crate::agent::production_owner::AgentProductionOwnerError>
    where
        P: crate::agent::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
        R: crate::agent::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
        I: crate::agent::clean_authority_issuer::CleanManagementIssuerStore + Send + 'static,
        F: crate::agent::local_lifecycle::LocalLifecycleStoreFactory + Send + 'static,
        F::Intent: crate::agent::local_lifecycle::NativeExternalIntentStore + Send + 'static,
        F::Issuer: Send + 'static,
        S: crate::agent::clean_authority_issuer::CleanManagementReceiptSigner + Send + 'static,
    {
        if self.clean_agent_owner.is_some() || self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::production_owner::AgentProductionOwnerError::DuplicateHost);
        }
        let owner = crate::agent::production_owner::AgentProductionOwner::start_local(
            node,
            limits,
            Box::new(lifecycle),
            queue_capacity,
            authenticator,
            reconcile_interval,
        )?;
        self.attach_clean_agent_owner(owner)?;
        if self.clean_local_lifecycle_queue.open().is_err() || self.shutdown.load(Ordering::Acquire)
        {
            self.signal_node_shutdown();
            return Err(
                crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration,
            );
        }
        Ok(())
    }

    /// Signed Local Create through the retained lifecycle controller, followed
    /// by authenticated route reconciliation. A failure after application is
    /// retryable only with the same signed request; it is not a rollback.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn create_clean_local_agent(
        &mut self,
        descriptor: crate::agent::sdk::AgentDescriptor,
        call: crate::agent::sdk::authority::AuthorityCredentialCall,
        runtime: crate::agent::package_admission::AdmittedRuntimePackage,
    ) -> crate::agent::local_lifecycle::LocalCreateResult {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(
                crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration,
            );
        }
        self.clean_agent_owner
            .as_ref()
            .ok_or(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)?
            .call(move |owner| {
                owner.ok_or(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)?
                    .create_local_disposition(descriptor, call, runtime)
            })?
    }

    /// Signed ordinary Shared Create through the retained lifecycle controller,
    /// followed by authenticated route reconciliation. A failure after
    /// application is retryable only with the same signed submission.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn create_clean_shared_agent(
        &mut self,
        submission: crate::agent::local_lifecycle::SharedCreateSubmission,
    ) -> crate::agent::local_lifecycle::SharedCreateResult {
        use crate::agent::production_owner::AgentProductionOwnerError;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        self.clean_agent_owner
            .as_ref()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?
            .call(move |owner| {
                owner
                    .ok_or(AgentProductionOwnerError::InvalidConfiguration)?
                    .create_shared_agent(submission)
            })?
    }

    /// Signed ordinary Shared Install through the retained lifecycle controller
    /// and verified actor-route publication. Exact retries keep the original
    /// signed terminal.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn install_clean_shared_actor(
        &mut self,
        submission: crate::agent::local_lifecycle::SharedInstallSubmission,
    ) -> crate::agent::local_lifecycle::SharedInstallResult {
        use crate::agent::production_owner::AgentProductionOwnerError;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        self.clean_agent_owner
            .as_ref()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?
            .call(move |owner| {
                owner
                    .ok_or(AgentProductionOwnerError::InvalidConfiguration)?
                    .install_shared_actor(submission)
            })?
    }

    /// Native policy decision: issued authorization or synchronized signed denial.
    /// Issuance is not actor application or application retirement. Callers must
    /// retain exact context/slot inputs for retry.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn authorize_clean_agent_operation(
        &mut self,
        call: &crate::agent::sdk::authority_operation::AuthorityOperationCall,
        context: crate::agent::sdk::InvocationContext,
        issued_at: u64,
    ) -> Result<
        crate::agent::clean_bootstrap::NativeAuthorityOperationDecision,
        crate::agent::shared_host::SharedAgentHostError,
    > {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(crate::agent::shared_host::SharedAgentHostError::Unavailable);
        }
        let call = call.clone();
        self.clean_agent_owner
            .as_ref()
            .ok_or(crate::agent::shared_host::SharedAgentHostError::Unavailable)?
            .call(move |owner| {
                owner
                    .ok_or(crate::agent::shared_host::SharedAgentHostError::Unavailable)?
                    .authorize_operation(&call, context, issued_at)
            })
            .map_err(|_| crate::agent::shared_host::SharedAgentHostError::Unavailable)?
    }

    /// Attach the native owner. Normal ingress is exposed only after initial
    /// authenticated reconciliation; retained recovery keeps that slot empty.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub(crate) fn attach_clean_agent_owner(
        &mut self,
        owner: crate::agent::production_owner::AgentProductionOwner,
    ) -> Result<(), crate::agent::production_owner::AgentProductionOwnerError> {
        use crate::agent::production_owner::AgentProductionOwnerError;

        if self.clean_agent_owner.is_some()
            || self.shutdown.load(Ordering::Acquire)
            || !owner.is_running()
        {
            let _ = owner.shutdown_and_join();
            return Err(AgentProductionOwnerError::DuplicateHost);
        }
        let handle = if owner.is_ready() {
            Some(owner.ingress()?)
        } else {
            None
        };
        let Ok(mut exposed) = self.clean_agent_ingress_supervisor.write() else {
            let _ = owner.shutdown_and_join();
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        };
        self.clean_agent_recovering
            .store(handle.is_none(), Ordering::Release);
        *exposed = handle;
        drop(exposed);
        self.clean_agent_owner = Some(
            crate::agent::production_worker::AgentProductionWorker::start(
                owner,
                self.shutdown.clone(),
                self.clean_agent_ingress_supervisor.clone(),
                self.clean_agent_recovering.clone(),
                self.clean_local_lifecycle_queue.clone(),
            )?,
        );
        Ok(())
    }

    /// Clone the read-only clean supervisor dispatch handle. Lifecycle and
    /// publication remain sealed inside the node-owned production owner.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn clean_agent_supervisor(
        &self,
    ) -> Option<crate::agent::supervisor::AgentSupervisorHandle> {
        self.clean_agent_ingress_supervisor
            .read()
            .ok()
            .and_then(|ingress| ingress.as_ref().map(|ingress| ingress.supervisor.clone()))
    }

    /// Hand one physical Local worker to the installed production owner. It
    /// stays unpublished until the next complete authority reconciliation.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn attach_clean_local_routes(
        &mut self,
        attachment: crate::agent::supervisor_adapters::AgentRouteHostAttachment,
    ) -> Result<(), crate::agent::production_owner::AgentProductionOwnerError> {
        match self.clean_agent_owner.as_mut() {
            Some(worker) => worker.call(move |owner| match owner {
                Some(owner) => owner.install_local_host(attachment),
                None => {
                    attachment.retire()?;
                    Err(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)
                }
            })?,
            None => {
                attachment.retire()?;
                Err(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)
            }
        }
    }

    /// Hand one physical Shared worker to the installed production owner. It
    /// stays unpublished until the next complete authority reconciliation.
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    pub fn attach_clean_shared_routes(
        &mut self,
        attachment: crate::agent::supervisor_adapters::AgentRouteHostAttachment,
    ) -> Result<(), crate::agent::production_owner::AgentProductionOwnerError> {
        match self.clean_agent_owner.as_mut() {
            Some(worker) => worker.call(move |owner| match owner {
                Some(owner) => owner.install_shared_host(attachment),
                None => {
                    attachment.retire()?;
                    Err(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)
                }
            })?,
            None => {
                attachment.retire()?;
                Err(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration)
            }
        }
    }

    /// Invoke one full-ID Local Agent actor and wait until its durable outcome
    /// is settled. Pending Merge execution is finalized inside the host and is
    /// never exposed through this node boundary.
    pub fn invoke_local_agent_synchronous(
        &self,
        agent: crate::service::AgentId,
        invocation: crate::agent::execution::ActorInvocation,
        authority: crate::agent::authority::ActorInvocationReceipt,
    ) -> Result<crate::agent::execution::ActorExecutionReply, crate::agent::host::AgentHostError>
    {
        self.local_agent_host
            .as_ref()
            .ok_or(crate::agent::host::AgentHostError::Unavailable)?
            .invoke(agent, invocation, authority)
    }

    /// Durably acknowledge one full-ID Local Agent invocation and wait for
    /// the acknowledgement or an exact divergence result.
    pub fn acknowledge_local_agent_invocation_synchronous(
        &self,
        agent: crate::service::AgentId,
        invocation: crate::agent::execution::ActorInvocation,
        authority: crate::agent::authority::ActorInvocationReceipt,
    ) -> Result<(), crate::agent::host::AgentHostError> {
        self.local_agent_host
            .as_ref()
            .ok_or(crate::agent::host::AgentHostError::Unavailable)?
            .acknowledge_invocation(agent, invocation, authority)
    }

    /// Insert `bytes` into the proof-blob store. Returns the
    /// content address (32-byte blake2b-256 of the bytes under the
    /// `"vos/proof-blob"` domain tag).
    ///
    /// Idempotent on equal bytes; the hash is collision-resistant.
    /// Used by producers to stash a STARK proof before sending a
    /// message whose proof-reference field carries the returned hash.
    ///
    /// When [`proof_blobs_dir`](Self::with_proof_blobs_dir) is set,
    /// also writes the bytes to `{dir}/{hex_hash}`. Disk errors are
    /// logged at `warn!` and ignored — the hot cache still has the
    /// blob, so the local node stays functional; only persistence
    /// across restarts is lost on a disk failure.
    pub fn put_proof_blob(&self, bytes: Vec<u8>) -> [u8; 32] {
        let hash = proof_blob_hash(&bytes);
        if let Some(dir) = &self.proof_blobs_dir {
            let path = dir.join(proof_blob_filename(&hash));
            if !path.exists()
                && let Err(e) = std::fs::write(&path, &bytes)
            {
                warn!(error = %e, path = %path.display(), "proof_blobs: disk write failed");
            }
        }
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(hash, bytes);
        }
        hash
    }

    /// Look up a proof blob by hash. Returns `None` when neither
    /// the hot cache nor disk (if configured) holds the blob.
    /// Cross-node fetch (cycle A1+A2) layers on top of this; a
    /// successful network fan-out caches into both tiers.
    pub fn get_proof_blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.proof_blobs.read().ok()?.get(hash).cloned() {
            return Some(bytes);
        }
        // Hot-cache miss: try disk if we have a backing directory.
        let dir = self.proof_blobs_dir.as_ref()?;
        let path = dir.join(proof_blob_filename(hash));
        let bytes = std::fs::read(&path).ok()?;
        // Hydrate the hot cache so the next lookup is fast.
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(*hash, bytes.clone());
        }
        Some(bytes)
    }

    /// Pre-populate the manifest payload exposed to peers via
    /// `Frame::ManifestReq`. Set-once: a second call is a
    /// programming error and is silently ignored. Call before
    /// [`attach_network`](Self::attach_network) — the
    /// `NetworkService` snapshot taken there reads from this slot.
    /// `vosx space up` calls this with the parsed `space.toml` bytes
    /// plus every actor blob so a joining node (`vosx space up
    /// <token>`) can fetch the cluster's manifest without a local recipe.
    #[cfg(feature = "network")]
    pub fn set_manifest(&self, reply: crate::network::ManifestReply) {
        let _ = self.manifest.set(reply);
    }

    /// Record this daemon's operator — the PeerId bytes of the CLI identity
    /// that started it (`vosx space up` loads the operator's
    /// `vosx/identity.key`). The value is threaded into the [`NodeService`]
    /// at [`attach_network`](Self::attach_network), where the locality gate
    /// admits this caller — and only this caller — to a node-confined agent.
    /// Call before `attach_network`; afterwards the service holds its own
    /// copy.
    #[cfg(feature = "network")]
    pub fn set_operator_peer(&mut self, peer_bytes: Vec<u8>) {
        self.operator_peer = Some(peer_bytes);
    }

    /// This daemon's operator PeerId bytes (the identity that ran `vosx
    /// space up`), if one was recorded. Lets boot-time reconcile tell
    /// "I am the space admin" (operator == registry root / has an ADMIN
    /// grant) from "I am a non-admin joiner", so a catalog op refused
    /// because the signer can't author isn't misread as the benign
    /// awaiting-sync case.
    #[cfg(feature = "network")]
    pub fn operator_peer(&self) -> Option<&[u8]> {
        self.operator_peer.as_deref()
    }

    /// Install the operator callback used for root-host attestations. The
    /// callback remains in [`NodeService`] and is never exposed to a guest or
    /// registry agent thread. Catalog mutations must already contain their
    /// caller-authored signature when dispatched.
    pub fn set_operator_signer<F>(&mut self, signer: F)
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.operator_signer = Some(Arc::new(signer));
    }

    /// Attach a libp2p [`Network`](crate::network::Network) so the
    /// node can route to and from peers.
    ///
    /// After this call:
    /// - [`route`](Self::route) forwards any envelope whose target
    ///   `node_prefix` doesn't match this node over the wire (via
    ///   the network's `peer_for_prefix` lookup).
    /// - A bridge thread reads inbound `Tell` frames from the
    ///   network and feeds them back into this node's outbox, so
    ///   they're routed by the same path local-only traffic uses.
    ///
    /// The bridge thread exits cleanly when either the network's
    /// inbox closes (because the [`Network`](crate::network::Network)
    /// is dropping) or the outbox closes (because the node is
    /// being collected).
    #[cfg(feature = "network")]
    pub fn attach_network(&mut self, network: crate::network::Network) {
        assert_eq!(
            self.node_prefix,
            network.local_prefix(),
            "VosNode prefix must match the authenticated network prefix"
        );
        // Install the unified service first so any inbound frame
        // that arrives between now and the bridge starting gets
        // resolved against this node's tables (invoke_routes,
        // crdt_replicas, host-supplied manifest) rather than the
        // trait's empty-reply defaults.
        let service = Arc::new(NodeService {
            invoke_routes: self.invoke_routes.clone(),
            service_actor_routes: self.service_actor_routes.clone(),
            agent_names: self.agent_names.clone(),
            agent_shutdown: self.agent_shutdown.clone(),
            agent_info: self.agent_info.clone(),
            #[cfg(feature = "storage")]
            replicas: self.crdt_replicas.clone(),
            #[cfg(feature = "storage")]
            raft_hosts: self.raft_hosts.clone(),
            #[cfg(feature = "storage")]
            service_private_ingress_routes: self.service_private_ingress_routes.clone(),
            shared_network: self.shared_network.clone(),
            manifest: self.manifest.clone(),
            proof_blobs: self.proof_blobs.clone(),
            proof_blobs_dir: self.proof_blobs_dir.clone(),
            program_blobs_dir: self.program_blobs_dir.clone(),
            operator_peer: self.operator_peer.clone(),
            operator_signer: self.operator_signer.clone(),
            #[cfg(feature = "storage")]
            sync_floor_cache: Arc::new(RwLock::new(HashMap::new())),
        });
        network.set_service(service);

        let inbox_rx = match network.take_inbox() {
            Some(rx) => rx,
            None => {
                warn!("network already had its inbox taken; bridge will not run");
                *self.shared_network.lock().unwrap() = Some(Arc::new(network));
                return;
            }
        };

        let outbox_tx = self.outbox_tx.clone();
        let activity = self.last_activity.clone();
        let shutdown = self.shutdown.clone();
        let service_actor_routes = self.service_actor_routes.clone();
        #[cfg(feature = "storage")]
        let invoke_routes = self.invoke_routes.clone();
        let network = Arc::new(network);
        #[cfg(feature = "storage")]
        let bridge_network = network.clone();
        thread::spawn(move || {
            for tell in inbox_rx {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if tell.payload.starts_with(b"VRTW") {
                    use crate::service::ServiceWire;

                    let peer = tell.peer.to_bytes();
                    let crdt_sync = crate::service::RootTreeTransport::decode(&tell.payload)
                        .ok()
                        .is_some_and(|transport| {
                            matches!(
                                transport,
                                crate::service::RootTreeTransport::CrdtSyncChunk { .. }
                                    | crate::service::RootTreeTransport::CrdtSyncAccepted { .. }
                            )
                        });
                    // The bridge binds the transport route to the complete
                    // Noise peer without blocking the global network thread
                    // on registry I/O. The destination root thread performs
                    // the exact enrolled-node lookup before exposing any
                    // receipt verifier decision to guest Accumulate.
                    let authenticated_crdt = crdt_sync
                        && crate::network::derive_node_prefix(&tell.peer)
                            == ServiceId(tell.from).node_prefix();
                    let authenticated = authenticated_crdt
                        || (!crdt_sync
                            && service_transport_source_route(
                                &service_actor_routes,
                                &tell.payload,
                            )
                            .is_some_and(|route| {
                                match route.consistency {
                                    crate::service::ConsistencyMode::Local => {
                                        route.route == tell.from
                                            && route.authenticated_peer.as_deref()
                                                == Some(peer.as_slice())
                                    }
                                    #[cfg(feature = "storage")]
                                    crate::service::ConsistencyMode::Raft => {
                                        raft_route_peer_is_current_leader(
                                            &route,
                                            ServiceId(tell.from),
                                            &peer,
                                            &bridge_network,
                                            &invoke_routes,
                                        )
                                    }
                                    _ => false,
                                }
                            }));
                    if !authenticated {
                        warn!(
                            peer = %tell.peer,
                            from = tell.from,
                            "node: rejected service root transport from an unbound authenticated peer"
                        );
                        continue;
                    }
                }
                *activity.lock().unwrap() = Instant::now();
                let env = Envelope {
                    from: ServiceId(tell.from),
                    to: ServiceId(tell.to),
                    payload: tell.payload,
                    authenticated_source_peer: Some(tell.peer.to_bytes()),
                    destination_peer: None,
                };
                if outbox_tx.send(env).is_err() {
                    break;
                }
            }
        });

        *self.shared_network.lock().unwrap() = Some(network);
    }

    /// Allocate the next service ID on this node.
    fn alloc_id(&self) -> ServiceId {
        let local = self.next_local.fetch_add(1, Ordering::Relaxed);
        ServiceId::new(self.node_prefix, local)
    }

    /// Record an installed instance name in the [`AgentNames`] reverse
    /// map under its local id. Called by both `register_inner` and
    /// `register_extension_inner` so every registered service is
    /// resolvable name-from-id by the auth path.
    ///
    /// The well-known `space-registry` name is filled in for the
    /// registry's fixed id even when the caller passed no name (vosx
    /// registers the registry from a bare `AgentConfig`), so the gate
    /// resolves the registry through the map uniformly instead of via a
    /// hardcoded special case. A WARN fires when an insert would
    /// overwrite a *different* existing name — a `local_id` collision in
    /// the ~15-bit instance space (`instance_service_id` masks to
    /// `0x100..=0x7FFF`); last-writer-wins, matching the registry's own
    /// id derivation.
    fn record_agent_name(&self, id: ServiceId, name: Option<String>) {
        let local = local_id_of(id.0);
        let name = name.or_else(|| {
            (local == ServiceId::REGISTRY.local_id()).then(|| REGISTRY_AGENT_NAME.to_string())
        });
        let Some(name) = name else { return };
        let Ok(mut map) = self.agent_names.write() else {
            return;
        };
        if let Some(prev) = map.get(&local) {
            if prev != &name {
                warn!(
                    local_id = local,
                    previous = %prev,
                    new = %name,
                    "register: instance-name collision on local id; \
                     auth reverse-lookup will use the latest name"
                );
            }
        }
        map.insert(local, name);
    }

    /// Resolve a (possibly prefix-scoped) `ServiceId` value back to the
    /// installed instance name registered for it, if any. The public
    /// reverse lookup backing actor-local grant probes and `intra_caps`
    /// targeting. Returns `None` for ids this node never registered
    /// (anonymous agents, cross-node targets the gate doesn't run for).
    pub fn agent_name_for(&self, svc_id: u32) -> Option<String> {
        self.agent_names
            .read()
            .ok()?
            .get(&local_id_of(svc_id))
            .cloned()
    }

    /// Register an agent at an explicit `ServiceId` instead of
    /// auto-allocating one. Used for well-known slots like the
    /// hyperspace registry which always lives at
    /// [`ServiceId::REGISTRY`] (== `ServiceId(0)`) so any agent
    /// can address it by a stable id without a name lookup.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_at_id(&mut self, config: AgentConfig, id: ServiceId) -> ServiceId {
        self.register_inner(config, id)
    }

    /// Attach one already-opened guest-owned service root tree to a local host
    /// route. Direct public and canonical space-role calls execute through the
    /// service PVM; this thread never applies actor writes or effects natively.
    pub fn register_service_root_at_id<B>(
        &mut self,
        name: impl Into<String>,
        mut service: crate::service::LocalRootTreeService<B>,
        id: ServiceId,
        network_reachable: bool,
    ) -> Result<ServiceId, NodeRegistrationError>
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        install_service_root_proof_verifier(&mut service, None)?;
        self.validate_service_root_registration(&service, id)?;
        Ok(self.attach_service_root_unchecked(name.into(), service, id, network_reachable, None))
    }

    /// Attach a service root with an explicit proof producer. Only roots registered
    /// through this capability may execute methods whose signed policy is
    /// attested; ordinary registration remains fail-closed.
    pub fn register_service_root_at_id_with_producer<B, P>(
        &mut self,
        name: impl Into<String>,
        mut service: crate::service::LocalRootTreeService<B>,
        id: ServiceId,
        network_reachable: bool,
        producer: P,
    ) -> Result<ServiceId, NodeRegistrationError>
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        P: crate::AttestationProofBackend + Send + 'static,
    {
        let producer = NodeAttestationProofProducer::new(producer);
        install_service_root_proof_verifier(&mut service, Some(producer.verifier()))?;
        self.validate_service_root_registration(&service, id)?;
        Ok(self.attach_service_root_unchecked(
            name.into(),
            service,
            id,
            network_reachable,
            Some(producer),
        ))
    }

    /// Attach a root which may verify proof-bearing replies but does not own a
    /// producer. This is the least-authority registration for callers of an
    /// attested peer: incoming proofs are checked independently, while direct
    /// and inbox methods requiring proof production remain fail-closed.
    pub fn register_service_root_at_id_with_verifier<B, V>(
        &mut self,
        name: impl Into<String>,
        mut service: crate::service::LocalRootTreeService<B>,
        id: ServiceId,
        network_reachable: bool,
        verifier: V,
    ) -> Result<ServiceId, NodeRegistrationError>
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        V: crate::AttestationProofVerifier + Send + 'static,
    {
        install_service_root_proof_verifier(
            &mut service,
            Some(service_node_attestation_proof_verifier(verifier)),
        )?;
        self.validate_service_root_registration(&service, id)?;
        Ok(self.attach_service_root_unchecked(name.into(), service, id, network_reachable, None))
    }

    fn validate_service_root_registration<B>(
        &self,
        service: &crate::service::LocalRootTreeService<B>,
        id: ServiceId,
    ) -> Result<(), NodeRegistrationError>
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            >,
    {
        if self.routes.contains_key(&id.0)
            || self.agent_info.read().unwrap().contains_key(&id.0)
            || self.invoke_routes.lock().unwrap().contains_key(&id.0)
        {
            return Err(NodeRegistrationError::ServiceRouteOccupied(id));
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        if self
            .pending_service_root_ids
            .lock()
            .unwrap()
            .contains(&id.0)
        {
            return Err(NodeRegistrationError::ServiceRouteOccupied(id));
        }
        let actor = service.root_actor();
        restore_service_root_logical_timeslot(service, &self.service_logical_timeslot)?;
        if self
            .service_actor_routes
            .read()
            .unwrap()
            .contains_key(&actor)
        {
            return Err(NodeRegistrationError::ActorAlreadyRegistered(actor));
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        if self
            .pending_service_root_actors
            .lock()
            .unwrap()
            .contains(&actor)
        {
            return Err(NodeRegistrationError::ActorAlreadyRegistered(actor));
        }
        Ok(())
    }

    fn attach_service_root_unchecked<B>(
        &mut self,
        name: String,
        mut service: crate::service::LocalRootTreeService<B>,
        id: ServiceId,
        network_reachable: bool,
        proof_producer: Option<NodeAttestationProofProducer>,
    ) -> ServiceId
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        let native_extension_caps = service.intra_caps().to_vec();
        let native_extension_consistency = service.consistency();
        service.set_native_extension_invoker(Arc::new(ServiceNativeExtensionInvoker {
            caller: id,
            consistency: native_extension_consistency,
            timeout: ASK_TIMEOUT,
            caps: native_extension_caps,
            invoke_routes: self.invoke_routes.clone(),
            agent_info: self.agent_info.clone(),
        }));
        let actor = service.root_actor();
        let is_role_authority = name == crate::service::ROLE_AUTHORITY_INSTANCE_;
        let root_name = name.clone();
        #[cfg(all(feature = "storage", feature = "network"))]
        let invoke_timeout = service
            .raft_propose_timeout_ms()
            .map(service_raft_invoke_timeout)
            .unwrap_or(SERVICE_LOCAL_INVOKE_TIMEOUT);
        #[cfg(not(all(feature = "storage", feature = "network")))]
        let invoke_timeout = SERVICE_LOCAL_INVOKE_TIMEOUT;
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(replication_id) = service.replication_id() {
            self.raft_hosts.lock().unwrap().insert(id.0, replication_id);
        }
        let service_identity = service.identity().clone();
        let consistency = match service.consistency() {
            crate::service::ConsistencyMode::Ephemeral => Consistency::Ephemeral,
            crate::service::ConsistencyMode::Local => Consistency::Local,
            crate::service::ConsistencyMode::Raft => Consistency::Raft,
            crate::service::ConsistencyMode::Crdt => Consistency::Crdt,
        };
        {
            let mut actors = self.service_actor_routes.write().unwrap();
            actors.insert(
                actor,
                ActorRoute {
                    route: id.0,
                    service: service_identity,
                    consistency: service.consistency(),
                    replication_id: service.replication_id(),
                    is_role_authority,
                    invoke_timeout,
                    authenticated_peer: None,
                },
            );
        }
        let (inbox_tx, inbox_rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        self.routes.insert(id.0, inbox_tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);
        self.record_agent_name(id, Some(name.clone()));
        self.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: Some(name),
                consistency: Some(consistency),
                network_reachable,
            },
        );
        let shutdown = self.register_agent_shutdown(id);
        let activity = self.last_activity.clone();
        let actor_routes = self.service_actor_routes.clone();
        let invoke_routes = self.invoke_routes.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();
        let logical_timeslot = self.service_logical_timeslot.clone();
        let outbox = self.outbox_tx.clone();
        #[cfg(all(feature = "network", feature = "storage"))]
        let private_ingress_registration = service.replication_id().map(|replication_id| {
            let (tx, rx) = mpsc::sync_channel(SERVICE_PRIVATE_INGRESS_QUEUE_CAPACITY);
            let (quiescence_tx, quiescence_rx) = mpsc::sync_channel(1);
            let route = Arc::new(PrivateIngressRoute {
                tx,
                quiescence_tx,
                barrier: PrivateIngressBarrier::new(),
                production_trust_policy: service.production_trust_policy_id().map(Into::into),
            });
            self.service_private_ingress_routes
                .write()
                .unwrap()
                .insert(replication_id, route.clone());
            PrivateIngressRegistration {
                replication_id,
                route,
                receiver: rx,
                quiescence_receiver: quiescence_rx,
                routes: self.service_private_ingress_routes.clone(),
            }
        });
        self.agents.push(AgentHandle {
            join: Some(thread::spawn(move || {
                service_root_service_thread(
                    id,
                    root_name,
                    service,
                    inbox_rx,
                    invoke_rx,
                    outbox,
                    actor_routes,
                    invoke_routes,
                    is_role_authority,
                    #[cfg(feature = "network")]
                    shared_network,
                    proof_producer,
                    #[cfg(all(feature = "network", feature = "storage"))]
                    private_ingress_registration,
                    logical_timeslot,
                    shutdown,
                    activity,
                )
            })),
        });
        id
    }

    /// Attach one Raft-backed service root tree to the node. The worker orders
    /// canonical `AccumulateRequest` bytes; the root thread applies the
    /// committed log through the same physical service PVM as local roots.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id<B>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        self.register_service_raft_root_at_id_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            None,
            None,
        )
    }

    /// Attach a Raft-backed root whose recovery, replay, and new admissions
    /// all use one fail-closed production trust policy. The capability is
    /// installed before the worker's committed log can be applied, so an
    /// empty or lagging replica cannot transiently execute through the local
    /// conformance allowlists.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_production<B>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        trust: Arc<dyn crate::service::ProductionTrust>,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        self.register_service_raft_root_at_id_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            None,
            Some(trust),
        )
    }

    /// Raft-backed counterpart of [`Self::register_service_root_at_id_with_producer`].
    /// The producer runs only on the current leader; the final proof-bearing
    /// Apply and proof bytes are quorum ordered for deterministic follower
    /// replay.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_with_producer<B, P>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        producer: P,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        P: crate::AttestationProofBackend + Send + 'static,
    {
        let producer = NodeAttestationProofProducer::new(producer);
        let verifier = producer.verifier();
        self.register_service_raft_root_at_id_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            Some(verifier),
            Some(producer),
            None,
        )
    }

    /// Production-trust counterpart of
    /// [`Self::register_service_raft_root_at_id_with_producer`]. Proof production
    /// remains leader-local, while the supplied production policy verifies
    /// the resulting public input on the leader before proposal and on every
    /// replica during replay.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_production_with_producer<B, P>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        trust: Arc<dyn crate::service::ProductionTrust>,
        producer: P,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        P: crate::AttestationProofBackend + Send + 'static,
    {
        let producer = NodeAttestationProofProducer::new(producer);
        self.register_service_raft_root_at_id_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            Some(producer),
            Some(trust),
        )
    }

    /// Raft-backed verifier-only registration for callers of attested roots.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_with_verifier<B, V>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        verifier: V,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        V: crate::AttestationProofVerifier + Send + 'static,
    {
        self.register_service_raft_root_at_id_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            Some(service_node_attestation_proof_verifier(verifier)),
            None,
            None,
        )
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    fn register_service_raft_root_at_id_inner<B>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        proof_verifier: Option<NodeAttestationProofVerifier>,
        proof_producer: Option<NodeAttestationProofProducer>,
        production_trust: Option<Arc<dyn crate::service::ProductionTrust>>,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        let mut prepared = self.prepare_service_raft_root(
            config,
            backend,
            db,
            raft_config,
            proof_verifier,
            production_trust,
        )?;
        if prepared.service.is_none() {
            return self.recover_persisted_service_raft_root(
                name,
                id,
                network_reachable,
                proof_producer,
                prepared,
            );
        }
        let mut service = prepared.service.take().unwrap();
        let replication_id = prepared.runtime.replication_id;
        let expected_policy = prepared.runtime.expected_policy;
        if let Some(expected_policy) = expected_policy {
            let installed = match service.catch_up() {
                Ok(installed) => installed,
                Err(_error) if prepared.runtime.retain_replica => {
                    prepared.service = Some(service);
                    return self.recover_persisted_service_raft_root(
                        name,
                        id,
                        network_reachable,
                        proof_producer,
                        prepared,
                    );
                }
                Err(error) => {
                    prepared
                        .runtime
                        .cleanup(&self.service_private_ingress_routes);
                    return Err(RaftNodeRegistrationError::CatchUp(error));
                }
            };
            if !installed {
                if prepared.runtime.retain_replica {
                    prepared.service = Some(service);
                    return self.recover_persisted_service_raft_root(
                        name,
                        id,
                        network_reachable,
                        proof_producer,
                        prepared,
                    );
                }
                prepared
                    .runtime
                    .cleanup(&self.service_private_ingress_routes);
                return Err(RaftNodeRegistrationError::CatchUp(
                    crate::service::LocalRootTreeInvokeError::ServiceNotInstalled,
                ));
            }
            if service.production_trust_policy_id() != Some(expected_policy) {
                if prepared.runtime.retain_replica {
                    prepared.service = Some(service);
                    return self.recover_persisted_service_raft_root(
                        name,
                        id,
                        network_reachable,
                        proof_producer,
                        prepared,
                    );
                }
                prepared
                    .runtime
                    .cleanup(&self.service_private_ingress_routes);
                return Err(RaftNodeRegistrationError::ProductionPolicyMismatch);
            }
        }
        if let Err(error) = self.validate_service_root_registration(&service, id) {
            prepared
                .runtime
                .cleanup(&self.service_private_ingress_routes);
            return Err(RaftNodeRegistrationError::Registration(error));
        }
        // A healthy application image is not membership authority. The
        // latest effective configuration may only be a speculative joint
        // inclusion recovered from the log. Keep that replica live and
        // private until Raft proves a committed final voter set containing
        // this node, exactly as the application-recovery path does.
        if !prepared.runtime.membership_committed_final_local_voter() {
            if prepared.runtime.retain_replica {
                prepared.service = Some(service);
                return self.recover_persisted_service_raft_root(
                    name,
                    id,
                    network_reachable,
                    proof_producer,
                    prepared,
                );
            }
            prepared
                .runtime
                .cleanup(&self.service_private_ingress_routes);
            return Err(RaftNodeRegistrationError::Promotion(
                "local replica is not a committed final voter".into(),
            ));
        }
        self.raft_hosts.lock().unwrap().insert(id.0, replication_id);
        Ok(
            self.attach_service_root_unchecked(
                name,
                service,
                id,
                network_reachable,
                proof_producer,
            ),
        )
    }

    /// Keep an already-configured voter private but live while its service
    /// image is reopened and caught up. Persisted membership is consensus
    /// ownership: a transient application error cannot unregister the Raft
    /// handler or drop the worker that the remaining voters count for quorum.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    fn recover_persisted_service_raft_root<B>(
        &mut self,
        name: String,
        id: ServiceId,
        network_reachable: bool,
        proof_producer: Option<NodeAttestationProofProducer>,
        mut prepared: PreparedRaftRoot<B>,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        debug_assert!(prepared.runtime.retain_replica);
        let actor = prepared.runtime.config.root_actor;
        if self.routes.contains_key(&id.0)
            || self.agent_info.read().unwrap().contains_key(&id.0)
            || self.invoke_routes.lock().unwrap().contains_key(&id.0)
            || self
                .pending_service_root_ids
                .lock()
                .unwrap()
                .contains(&id.0)
        {
            prepared
                .runtime
                .cleanup(&self.service_private_ingress_routes);
            return Err(RaftNodeRegistrationError::Registration(
                NodeRegistrationError::ServiceRouteOccupied(id),
            ));
        }
        if self
            .service_actor_routes
            .read()
            .unwrap()
            .contains_key(&actor)
            || self
                .pending_service_root_actors
                .lock()
                .unwrap()
                .contains(&actor)
        {
            prepared
                .runtime
                .cleanup(&self.service_private_ingress_routes);
            return Err(RaftNodeRegistrationError::Registration(
                NodeRegistrationError::ActorAlreadyRegistered(actor),
            ));
        }

        self.pending_service_root_ids.lock().unwrap().insert(id.0);
        self.pending_service_root_actors
            .lock()
            .unwrap()
            .insert(actor);
        let ready_tx = self.pending_service_root_ready_tx.clone();
        let pending_ids = self.pending_service_root_ids.clone();
        let pending_actors = self.pending_service_root_actors.clone();
        let shutdown = self.shutdown.clone();
        let logical_timeslot = self.service_logical_timeslot.clone();
        let pending_routes = self.service_private_ingress_routes.clone();
        let join = thread::spawn(move || {
            let mut next_warning = Instant::now();
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    prepared.runtime.cleanup(&pending_routes);
                    pending_ids.lock().unwrap().remove(&id.0);
                    pending_actors.lock().unwrap().remove(&actor);
                    return;
                }
                if prepared
                    .runtime
                    .membership_definitively_removed_local_voter()
                {
                    prepared.runtime.cleanup(&pending_routes);
                    pending_ids.lock().unwrap().remove(&id.0);
                    pending_actors.lock().unwrap().remove(&actor);
                    return;
                }
                if prepared.service.is_none() {
                    match prepared.runtime.open() {
                        Ok(service) => prepared.service = Some(service),
                        Err(_) => {
                            if Instant::now() >= next_warning {
                                warn!(%id, "persisted service Raft voter is retrying service open/replay");
                                next_warning = Instant::now() + Duration::from_secs(5);
                            }
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    }
                }
                let service = prepared.service.as_mut().unwrap();
                let recovered = service.catch_up().is_ok_and(|installed| installed)
                    && prepared.runtime.expected_policy.is_none_or(|expected| {
                        service.production_trust_policy_id() == Some(expected)
                    })
                    && restore_service_root_logical_timeslot(service, &logical_timeslot).is_ok()
                    && prepared.runtime.membership_committed_final_local_voter();
                if recovered {
                    break;
                }
                if Instant::now() >= next_warning {
                    warn!(%id, "persisted service Raft voter remains private while catch-up retries");
                    next_warning = Instant::now() + Duration::from_secs(5);
                }
                thread::sleep(Duration::from_millis(100));
            }

            let service = prepared.service.take().unwrap();
            let runtime = prepared.runtime;
            let ready_handler = runtime.handler.clone();
            let ready_network = runtime.network.clone();
            let pending_route = runtime.pending_route.clone();
            let replication_id = runtime.replication_id;
            let ready_pending_ids = pending_ids.clone();
            let ready_pending_actors = pending_actors.clone();
            let ready: PendingRootReady = Box::new(move |node| {
                if node.shutdown.load(Ordering::Relaxed) {
                    if let Some(network) = ready_network.as_ref() {
                        network.unregister_raft_handler_if(&replication_id, &ready_handler);
                    }
                    remove_service_private_ingress_route_if(
                        &node.service_private_ingress_routes,
                        &replication_id,
                        &pending_route,
                    );
                    ready_pending_ids.lock().unwrap().remove(&id.0);
                    ready_pending_actors.lock().unwrap().remove(&actor);
                    return;
                }
                node.raft_hosts.lock().unwrap().insert(id.0, replication_id);
                node.attach_service_root_unchecked(
                    name,
                    service,
                    id,
                    network_reachable,
                    proof_producer,
                );
                ready_pending_ids.lock().unwrap().remove(&id.0);
                ready_pending_actors.lock().unwrap().remove(&actor);
            });
            if ready_tx.send(ready).is_err() {
                runtime.cleanup(&pending_routes);
                pending_ids.lock().unwrap().remove(&id.0);
                pending_actors.lock().unwrap().remove(&actor);
            }
        });
        self.pending_service_root_threads.push(join);
        Ok(id)
    }

    /// Start and validate a Raft replica before an optional voter-promotion
    /// handshake. Promotion and final-membership observation run on a
    /// shutdown-aware background worker; the root remains reserved but absent
    /// from public route tables until that worker hands it back to the router.
    /// The callback runs while the worker and inbound Raft handler are live, so
    /// joint consensus can replicate to the joiner immediately; any local
    /// open/route failure occurs before the existing cluster changes
    /// membership.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_after_local_attach<B, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        F: FnOnce(&crate::raft::WorkerHandle, &AtomicBool) -> Result<(), String> + Send + 'static,
    {
        self.register_service_raft_root_at_id_after_local_attach_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            None,
            None,
            move |worker, shutdown, _| promote(worker, shutdown),
        )
    }

    /// Prepare a production-trust Raft replica before voter promotion. The
    /// unopened route cannot participate in membership until the exact trust
    /// policy has accepted snapshot recovery, committed replay, and service
    /// genesis locally.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_after_local_attach_production<B, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        trust: Arc<dyn crate::service::ProductionTrust>,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        F: FnOnce(
                &crate::raft::WorkerHandle,
                &AtomicBool,
                crate::service::Hash,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        self.register_service_raft_root_at_id_after_local_attach_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            None,
            Some(trust),
            move |worker, shutdown, policy| {
                promote(
                    worker,
                    shutdown,
                    policy.expect("production preparation always has a policy"),
                )
            },
        )
    }

    /// Producer-capable counterpart of
    /// [`Self::register_service_raft_root_at_id_after_local_attach`]. The proof
    /// capability remains owned by the prepared replica and moves into the
    /// root thread only after voter promotion completes, so the replica is
    /// ready to prove attested direct and durable-inbox work before its route
    /// becomes public or it can serve as leader.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_after_local_attach_with_producer<B, P, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        producer: P,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        P: crate::AttestationProofBackend + Send + 'static,
        F: FnOnce(&crate::raft::WorkerHandle, &AtomicBool) -> Result<(), String> + Send + 'static,
    {
        let producer = NodeAttestationProofProducer::new(producer);
        let verifier = producer.verifier();
        self.register_service_raft_root_at_id_after_local_attach_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            Some(verifier),
            Some(producer),
            None,
            move |worker, shutdown, _| promote(worker, shutdown),
        )
    }

    /// Producer-capable production counterpart of
    /// [`Self::register_service_raft_root_at_id_after_local_attach_production`].
    /// The producer and trust capability remain private to the prepared
    /// replica and move into the root thread only after promotion succeeds.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_after_local_attach_production_with_producer<B, P, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        trust: Arc<dyn crate::service::ProductionTrust>,
        producer: P,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        P: crate::AttestationProofBackend + Send + 'static,
        F: FnOnce(
                &crate::raft::WorkerHandle,
                &AtomicBool,
                crate::service::Hash,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        let producer = NodeAttestationProofProducer::new(producer);
        self.register_service_raft_root_at_id_after_local_attach_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            None,
            Some(producer),
            Some(trust),
            move |worker, shutdown, policy| {
                promote(
                    worker,
                    shutdown,
                    policy.expect("production preparation always has a policy"),
                )
            },
        )
    }

    /// Verifier-only counterpart for a joining Raft caller of attested roots.
    /// The capability is installed before voter promotion, so follower replay
    /// can validate proof sidecars before the public route appears.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    pub fn register_service_raft_root_at_id_after_local_attach_with_verifier<B, V, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        verifier: V,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        V: crate::AttestationProofVerifier + Send + 'static,
        F: FnOnce(&crate::raft::WorkerHandle, &AtomicBool) -> Result<(), String> + Send + 'static,
    {
        self.register_service_raft_root_at_id_after_local_attach_inner(
            name,
            config,
            backend,
            db,
            raft_config,
            id,
            network_reachable,
            Some(service_node_attestation_proof_verifier(verifier)),
            None,
            None,
            move |worker, shutdown, _| promote(worker, shutdown),
        )
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    #[allow(clippy::too_many_arguments)]
    fn register_service_raft_root_at_id_after_local_attach_inner<B, F>(
        &mut self,
        name: String,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        id: ServiceId,
        network_reachable: bool,
        proof_verifier: Option<NodeAttestationProofVerifier>,
        proof_producer: Option<NodeAttestationProofProducer>,
        production_trust: Option<Arc<dyn crate::service::ProductionTrust>>,
        promote: F,
    ) -> Result<
        ServiceId,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
        F: FnOnce(
                &crate::raft::WorkerHandle,
                &AtomicBool,
                Option<crate::service::Hash>,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        let mut prepared = self.prepare_service_raft_root(
            config,
            backend,
            db,
            raft_config,
            proof_verifier,
            production_trust,
        )?;
        if prepared.runtime.retain_replica {
            return self.recover_persisted_service_raft_root(
                name,
                id,
                network_reachable,
                proof_producer,
                prepared,
            );
        }
        let mut service = prepared
            .service
            .take()
            .expect("a new joiner must open before voter promotion");
        let worker_handle = prepared.runtime.worker.handler();
        let network = prepared.runtime.network.clone();
        let replication_id = prepared.runtime.replication_id;
        let handler = prepared.runtime.handler.clone();
        let expected_policy = prepared.runtime.expected_policy;
        let pending_route = prepared.runtime.pending_route.clone();
        if let Err(error) = self.validate_service_root_registration(&service, id) {
            prepared
                .runtime
                .cleanup(&self.service_private_ingress_routes);
            return Err(RaftNodeRegistrationError::Registration(error));
        }

        let actor = service.root_actor();
        self.pending_service_root_ids.lock().unwrap().insert(id.0);
        self.pending_service_root_actors
            .lock()
            .unwrap()
            .insert(actor);
        let ready_tx = self.pending_service_root_ready_tx.clone();
        let pending_ids = self.pending_service_root_ids.clone();
        let pending_actors = self.pending_service_root_actors.clone();
        let shutdown = self.shutdown.clone();
        let cleanup_network = network.clone();
        let cleanup_handler = handler.clone();
        let pending_routes = self.service_private_ingress_routes.clone();
        let cleanup_pending_route = pending_route.clone();
        // Keep the shared worker/apply receiver alive independently of the
        // service while the promotion callback runs.
        let recovery_runtime = prepared.runtime;
        let join = thread::spawn(move || {
            let promotion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                promote(&worker_handle, &shutdown, expected_policy)
            }))
            .unwrap_or_else(|_| Err("prepared service Raft root promotion panicked".into()));
            let outcome = promotion.and_then(|()| {
                // `Ok(())` means final membership is committed. From here on
                // this worker is quorum state, not disposable registration
                // scaffolding. Keep serving Raft and retry application
                // catch-up until the local root is safe to publish or the
                // entire node shuts down.
                let mut next_warning = Instant::now();
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        return Err(
                            "node shut down while promoted service Raft root was catching up".into()
                        );
                    }
                    let recovery = match service.catch_up() {
                        Ok(true)
                            if expected_policy.is_none_or(|expected| {
                                service.production_trust_policy_id() == Some(expected)
                            }) => return Ok(()),
                        Ok(true) => "production trust policy still mismatches".to_owned(),
                        Ok(false) => "service genesis is not installed yet".to_owned(),
                        Err(error) => format!("catch-up failed: {error}"),
                    };
                    if Instant::now() >= next_warning {
                        warn!(%id, %recovery, "promoted service Raft root remains private while recovering");
                        next_warning = Instant::now() + Duration::from_secs(5);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
            if outcome.is_ok() && !shutdown.load(Ordering::Relaxed) {
                let ready_network = network.clone();
                let ready_pending_ids = pending_ids.clone();
                let ready_pending_actors = pending_actors.clone();
                let ready_handler = handler.clone();
                let ready: PendingRootReady = Box::new(move |node| {
                    if node.shutdown.load(Ordering::Relaxed) {
                        if let Some(network) = ready_network.as_ref() {
                            network.unregister_raft_handler_if(&replication_id, &ready_handler);
                        }
                        remove_service_private_ingress_route_if(
                            &node.service_private_ingress_routes,
                            &replication_id,
                            &pending_route,
                        );
                        ready_pending_ids.lock().unwrap().remove(&id.0);
                        ready_pending_actors.lock().unwrap().remove(&actor);
                        return;
                    }
                    node.raft_hosts.lock().unwrap().insert(id.0, replication_id);
                    node.attach_service_root_unchecked(
                        name,
                        service,
                        id,
                        network_reachable,
                        proof_producer,
                    );
                    ready_pending_ids.lock().unwrap().remove(&id.0);
                    ready_pending_actors.lock().unwrap().remove(&actor);
                });
                if ready_tx.send(ready).is_ok() {
                    return;
                }
            }

            if let Some(network) = cleanup_network.as_ref() {
                network.unregister_raft_handler_if(&replication_id, &cleanup_handler);
            }
            remove_service_private_ingress_route_if(
                &pending_routes,
                &replication_id,
                &cleanup_pending_route,
            );
            pending_ids.lock().unwrap().remove(&id.0);
            pending_actors.lock().unwrap().remove(&actor);
            if let Err(error) = outcome {
                warn!(%id, %error, "prepared service Raft root promotion deferred");
            }
            drop(recovery_runtime);
        });
        self.pending_service_root_threads.push(join);
        Ok(id)
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    fn prepare_service_raft_root<B>(
        &self,
        config: crate::service::LocalRootTreeConfig,
        backend: B,
        db: Arc<redb::Database>,
        raft_config: crate::raft::RaftConfig,
        proof_verifier: Option<NodeAttestationProofVerifier>,
        production_trust: Option<Arc<dyn crate::service::ProductionTrust>>,
    ) -> Result<
        PreparedRaftRoot<B>,
        RaftNodeRegistrationError<<B as crate::service::CommittedImageStore>::Error>,
    >
    where
        B: crate::service::CommittedImageStore
            + crate::service::ProofArtifactStore<
                Error = <B as crate::service::CommittedImageStore>::Error,
            > + Send
            + 'static,
    {
        // Refuse packages whose canonical Install entry cannot cross the
        // Raft network boundary before reserving a handler or spawning a
        // worker. `open_raft` repeats this validation at its own trust
        // boundary, but that is intentionally later than replica startup.
        config.validate().map_err(|error| {
            RaftNodeRegistrationError::Open(crate::service::LocalRootTreeOpenError::InvalidConfig(
                error,
            ))
        })?;
        let mut voter_peers = Vec::with_capacity(raft_config.voter_peer_ids.len());
        let mut voter_slots = BTreeMap::new();
        for (prefix, bytes) in &raft_config.voter_peer_ids {
            let peer = libp2p::PeerId::from_bytes(bytes)
                .map_err(|_| RaftNodeRegistrationError::InvalidVoterIdentity(*prefix))?;
            if crate::network::derive_node_prefix(&peer) != *prefix {
                return Err(RaftNodeRegistrationError::InvalidVoterIdentity(*prefix));
            }
            if voter_slots
                .insert(*prefix, peer)
                .is_some_and(|existing| existing != peer)
            {
                return Err(RaftNodeRegistrationError::InvalidVoterIdentity(*prefix));
            }
        }
        voter_peers.extend(voter_slots);
        let replication_id = raft_config.replication_id;
        let expected_policy = production_trust.as_ref().map(|trust| trust.policy_id());
        let persisted_config =
            crate::raft::log::load_active_config(&db).map_err(RaftNodeRegistrationError::Log)?;
        let persisted_commit_index = crate::raft::log::RaftMeta::load(&db)
            .map_err(RaftNodeRegistrationError::Log)?
            .commit_index;
        let mut retain_replica = persisted_config.is_some_and(|record| {
            record.current.contains(&raft_config.me)
                || record
                    .joint_old
                    .is_some_and(|members| members.contains(&raft_config.me))
                // A row without provenance or a configuration newer than commit_index
                // cannot prove that removal committed. Retain the worker so
                // it can still satisfy the last committed joint quorum.
                || record
                    .log_index
                    .is_none_or(|index| index > persisted_commit_index)
        });
        let pending_route = pending_service_private_ingress_route(expected_policy.map(Into::into));
        {
            let mut routes = self.service_private_ingress_routes.write().unwrap();
            if routes.contains_key(&replication_id) {
                return Err(RaftNodeRegistrationError::ReplicationHandlerOccupied(
                    replication_id,
                ));
            }
            routes.insert(replication_id, pending_route.clone());
        }
        let network = self
            .shared_network
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        let reservation = if let Some(network) = network.as_ref() {
            let Some(reservation) = network.reserve_raft_handler(replication_id) else {
                remove_service_private_ingress_route_if(
                    &self.service_private_ingress_routes,
                    &replication_id,
                    &pending_route,
                );
                return Err(RaftNodeRegistrationError::ReplicationHandlerOccupied(
                    replication_id,
                ));
            };
            Some(reservation)
        } else {
            None
        };
        let (apply_tx, apply_rx) = mpsc::channel::<u64>();
        let worker = crate::raft::RaftWorker::spawn(
            db.clone(),
            crate::raft::WorkerConfig {
                me: raft_config.me,
                members: raft_config.members.clone(),
                replication_id,
                election_timeout_ms: raft_config.election_timeout_ms,
                heartbeat_interval_ms: raft_config.heartbeat_interval_ms,
            },
            network.clone(),
            Some(apply_tx),
        );
        let worker_handle = worker.handler();
        // A removed replica remains a required private transport endpoint
        // until the surviving group commits its retirement-confirmation row.
        // The live log pair is more precise than the persisted active-config
        // row, which already contains the final membership at this point.
        retain_replica |= worker_handle.snapshot().is_some_and(|snapshot| {
            snapshot.retirement_final_index.is_some() && !snapshot.members.contains(&raft_config.me)
        });
        let handler: Arc<dyn crate::network::RaftRpcHandler> = Arc::new(worker_handle.clone());
        if let (Some(network), Some(reservation)) = (network.as_ref(), reservation.as_ref())
            && !network.activate_raft_handler_with_voters(
                reservation,
                handler.clone(),
                &voter_peers,
            )
        {
            worker.shutdown();
            remove_service_private_ingress_route_if(
                &self.service_private_ingress_routes,
                &replication_id,
                &pending_route,
            );
            return Err(RaftNodeRegistrationError::ReplicationHandlerOccupied(
                replication_id,
            ));
        }
        // Activation replaced the placeholder, so dropping the reservation is
        // now a no-op. Any earlier panic/error would instead remove only the
        // still-owned placeholder through its Drop implementation.
        drop(reservation);
        let runtime = RaftRecoveryRuntime {
            config,
            backend: NodeCommittedImageStore(Arc::new(Mutex::new(backend))),
            db,
            raft_config,
            worker: Arc::new(worker),
            apply_rx: Arc::new(Mutex::new(apply_rx)),
            network,
            replication_id,
            handler,
            expected_policy,
            pending_route,
            proof_verifier,
            production_trust,
            retain_replica,
        };
        match runtime.open() {
            Ok(service) => Ok(PreparedRaftRoot {
                service: Some(service),
                runtime,
            }),
            Err(error) if runtime.retain_replica => {
                let reason = match error {
                    RaftRecoveryOpenError::Log(_) => "Raft log open failed",
                    RaftRecoveryOpenError::Service(_) => "service image open/replay failed",
                };
                warn!(?replication_id, %reason, "persisted service Raft voter remains private while recovery retries");
                Ok(PreparedRaftRoot {
                    service: None,
                    runtime,
                })
            }
            Err(RaftRecoveryOpenError::Log(error)) => {
                runtime.cleanup(&self.service_private_ingress_routes);
                Err(RaftNodeRegistrationError::Log(error))
            }
            Err(RaftRecoveryOpenError::Service(error)) => {
                runtime.cleanup(&self.service_private_ingress_routes);
                Err(RaftNodeRegistrationError::Open(error))
            }
        }
    }

    /// Bind an externally owned service actor to an authenticated physical route.
    /// The caller must obtain `service` from trusted registry/consensus state;
    /// a peer transport envelope is never allowed to declare this mapping.
    pub fn bind_service_actor_route(
        &self,
        actor: crate::service::ActorId,
        service: crate::service::ServiceIdentity,
        consistency: crate::service::ConsistencyMode,
        route: ServiceId,
        authenticated_peer: Vec<u8>,
    ) -> Result<(), NodeRegistrationError> {
        if consistency == crate::service::ConsistencyMode::Raft {
            // A Raft route without its group identity would pin transport to
            // one replica and become unsafe/stuck after leadership changes.
            return Err(NodeRegistrationError::CorruptServiceStore);
        }
        self.bind_service_actor_route_inner(
            actor,
            service,
            consistency,
            None,
            route,
            authenticated_peer,
        )
    }

    /// Bind an externally owned Raft actor to one authenticated bootstrap
    /// replica and its exact replication group. Transport resolves the
    /// current leader from this group on every retry; the bootstrap peer is
    /// never treated as permanent authority.
    pub fn bind_service_raft_actor_route(
        &self,
        actor: crate::service::ActorId,
        service: crate::service::ServiceIdentity,
        replication_id: [u8; 32],
        route: ServiceId,
        authenticated_peer: Vec<u8>,
    ) -> Result<(), NodeRegistrationError> {
        if replication_id == [0; 32] {
            return Err(NodeRegistrationError::CorruptServiceStore);
        }
        self.bind_service_actor_route_inner(
            actor,
            service,
            crate::service::ConsistencyMode::Raft,
            Some(replication_id),
            route,
            authenticated_peer,
        )
    }

    fn bind_service_actor_route_inner(
        &self,
        actor: crate::service::ActorId,
        service: crate::service::ServiceIdentity,
        consistency: crate::service::ConsistencyMode,
        replication_id: Option<[u8; 32]>,
        route: ServiceId,
        authenticated_peer: Vec<u8>,
    ) -> Result<(), NodeRegistrationError> {
        if authenticated_peer.is_empty() {
            return Err(NodeRegistrationError::CorruptServiceStore);
        }
        #[cfg(feature = "network")]
        {
            let peer = libp2p::PeerId::from_bytes(&authenticated_peer)
                .map_err(|_| NodeRegistrationError::CorruptServiceStore)?;
            if route.node_prefix() != crate::network::derive_node_prefix(&peer) {
                return Err(NodeRegistrationError::CorruptServiceStore);
            }
        }
        let mut routes = self.service_actor_routes.write().unwrap();
        let candidate = ActorRoute {
            route: route.0,
            service,
            consistency,
            replication_id,
            is_role_authority: false,
            invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
            authenticated_peer: Some(authenticated_peer),
        };
        match routes.get(&actor) {
            Some(existing) if existing == &candidate => Ok(()),
            Some(_) => Err(NodeRegistrationError::ActorAlreadyRegistered(actor)),
            None => {
                routes.insert(actor, candidate);
                Ok(())
            }
        }
    }

    /// Register an agent and return its service ID.
    /// The agent starts immediately on a new thread.
    pub fn register(&mut self, config: AgentConfig) -> ServiceId {
        let id = self.alloc_id();
        self.register_inner(config, id)
    }

    // `config` is mutated only on the CRDT/Raft pre-open path (gated
    // all(storage, network)); without both, the `mut` is unused.
    #[cfg_attr(not(all(feature = "storage", feature = "network")), allow(unused_mut))]
    fn register_inner(&mut self, mut config: AgentConfig, id: ServiceId) -> ServiceId {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);
        self.record_agent_name(id, config.name.clone());
        // Monotone locality seal (immutable-local): a named agent's
        // shareability may only ever narrow, never widen — enforced
        // host-side, ahead of the sync-attach branches below, because the
        // registry row that carries `consistency` is replicated and not
        // trusted.
        #[cfg(feature = "storage")]
        config.apply_consistency_seal(id);
        // Actor metadata backing `__describe`.
        // `consistency` is recorded *after* the seal so the locality gate
        // sees the effective (possibly narrowed) tier, never a forged
        // registry row's requested one.
        self.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: config.name.clone(),
                consistency: Some(config.consistency),
                network_reachable: config.network_reachable,
            },
        );

        // Pre-open the redb database for CRDT actors that declare
        // a replication group, so the same `Arc<Database>` powers
        // both the agent's `CrdtCommit` and the network's
        // `SyncHandler`. redb is exclusive on file open, so this
        // is the only way to share the file across threads.
        //
        // When the file opens cleanly we also create a one-shot-
        // style notification channel: the per-replica sync ticker
        // pings the Sender after a non-empty merge, the agent
        // thread holds the Receiver and runs `soft_restart_crdt`
        // between dispatches to refresh its in-memory state.
        #[cfg(all(feature = "network", feature = "storage"))]
        let sync_rx: Option<mpsc::Receiver<()>> = if config.consistency == Consistency::Crdt {
            config.replication_id.and_then(|rep_id| {
                let path = config.db_path(id)?;
                match redb::Database::create(&path) {
                    Ok(db) => {
                        let slot = ReplicaSlot {
                            db: Arc::new(db),
                            commit_lock: Arc::new(Mutex::new(())),
                            name: config.name.clone().unwrap_or_default(),
                            node_validator: config.node_validator.clone(),
                        };
                        self.crdt_replicas
                            .lock()
                            .unwrap()
                            .insert(rep_id, slot.clone());
                        config.pre_opened_db = Some(slot.db.clone());
                        config.pre_opened_lock = Some(slot.commit_lock.clone());
                        let (sync_tx, sync_rx) = mpsc::channel::<()>();
                        self.spawn_sync_thread(rep_id, slot, Some(sync_tx));
                        Some(sync_rx)
                    }
                    Err(e) => {
                        error!(%id, error = %e, "register: failed to open CRDT db; \
                            replication will be inactive");
                        None
                    }
                }
            })
        } else if config.consistency == Consistency::Raft && !config.members.is_empty() {
            // Multi-mode Raft: spawn a worker, install it as the
            // network's RaftRpcHandler, and bridge the worker's
            // apply notifications into both (a) the agent's
            // sync_rx (so the soft-restart path catches up state
            // on followers) and (b) the strategy's apply_rx (so
            // the leader's commit_with_log unblocks once its
            // proposed entry commits).
            //
            // A single-element member list is the solo-bootstrap
            // case: the worker self-elects with a quorum of one
            // and can then admit joiners through `RaftJoinReq` —
            // unlike the memberless fallback below, which never
            // answers cluster RPCs. The persisted active config,
            // when present, supersedes `config.members` on boot.
            let network = self.shared_network.lock().ok().and_then(|g| g.clone());
            let rep_id = config.replication_id.unwrap_or([0u8; 32]);
            match config.db_path(id).map(|p| {
                let db = redb::Database::create(&p);
                (p, db)
            }) {
                Some((_path, Ok(db))) => {
                    let db = Arc::new(db);
                    config.pre_opened_db = Some(db.clone());

                    let worker_cfg = crate::raft::WorkerConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: rep_id,
                        election_timeout_ms: (150, 300),
                        heartbeat_interval_ms: 50,
                    };
                    let (worker_tx, worker_rx) = mpsc::channel::<u64>();
                    let worker = crate::raft::RaftWorker::spawn(
                        db.clone(),
                        worker_cfg,
                        network.clone(),
                        Some(worker_tx),
                    );
                    if let Some(net) = network.as_ref() {
                        net.register_raft_handler(rep_id, Arc::new(worker.handler()));
                    }
                    // Relay: each commit advance fans out to both
                    // the strategy's apply_rx and the agent's
                    // sync_rx. Lives until the worker drops its
                    // sender (either side closing is fine).
                    let (commit_tx, commit_rx) = mpsc::channel::<u64>();
                    let (sync_tx, sync_rx) = mpsc::channel::<()>();
                    thread::Builder::new()
                        .name(format!("raft-relay-{:08x}", id.0))
                        .spawn(move || {
                            while let Ok(idx) = worker_rx.recv() {
                                let _ = commit_tx.send(idx);
                                let _ = sync_tx.send(());
                            }
                        })
                        .expect("spawn raft relay");
                    config.raft_worker = Some(worker);
                    config.raft_apply_rx = Some(commit_rx);
                    // Record the group membership so the extension
                    // ask path can forward follower-rejected writes
                    // to the leader (see `RaftFwd` / `route_invoke`).
                    self.raft_hosts.lock().unwrap().insert(id.0, rep_id);
                    Some(sync_rx)
                }
                Some((path, Err(e))) => {
                    error!(%id, path = %path.display(), error = %e,
                        "register: failed to open Raft db; replication will be inactive");
                    None
                }
                None => None,
            }
        } else {
            None
        };

        let invoke_routes = self.invoke_routes.clone();
        // This agent polls its OWN shutdown flag (a node-wide
        // shutdown fans out to it), so the daemon can stop it individually.
        let shutdown = self.register_agent_shutdown(id);
        let activity = self.last_activity.clone();
        // Reverse svc-id → instance-name map, so an agent that opts into
        // bounded outbound relay (declared `intra_caps`) can resolve each
        // invoke target's name to pick its cap ceiling.
        let agent_names = self.agent_names.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();
        // Leader-forward plan for an agent that opted into bounded relay and
        // writes to a raft target: a follower that refuses the write (drops the
        // reply) is recognized + the write re-sent to the leader (mirrors the
        // extension ask path's `route_invoke`).
        let raft_fwd = RaftFwd {
            #[cfg(all(feature = "network", feature = "storage"))]
            network: self.shared_network.clone(),
            #[cfg(all(feature = "network", feature = "storage"))]
            hosts: self.raft_hosts.clone(),
        };
        let join = thread::spawn(move || {
            agent_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                agent_names,
                raft_fwd,
                shutdown,
                activity,
                #[cfg(feature = "network")]
                shared_network,
                #[cfg(all(feature = "network", feature = "storage"))]
                sync_rx,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Register a native extension at a freshly-allocated
    /// ServiceId. Waits until plugin loading, state restore, and the initial
    /// persistence check have succeeded before returning.
    pub fn register_extension(&mut self, config: ExtensionConfig) -> ServiceId {
        self.try_register_extension(config)
            .unwrap_or_else(|error| panic!("extension registration failed: {error}"))
    }

    /// Fallible extension registration. No route or agent metadata is
    /// published unless the worker acknowledges successful startup.
    pub fn try_register_extension(&mut self, config: ExtensionConfig) -> Result<ServiceId, String> {
        let id = self.alloc_id();
        self.register_extension_inner(config, id)
    }

    /// Register an extension at an explicit `ServiceId`. Mirrors
    /// [`register_at_id`](Self::register_at_id) for the actor side
    /// — used to slot a mock registry into `ServiceId::REGISTRY`
    /// (= 0) for tests and to install built-in service extensions
    /// at well-known ids.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_extension_at_id(
        &mut self,
        config: ExtensionConfig,
        id: ServiceId,
    ) -> ServiceId {
        self.try_register_extension_at_id(config, id)
            .unwrap_or_else(|error| panic!("extension registration failed for {id}: {error}"))
    }

    /// Fallible explicit-id variant of [`try_register_extension`](Self::try_register_extension).
    pub fn try_register_extension_at_id(
        &mut self,
        config: ExtensionConfig,
        id: ServiceId,
    ) -> Result<ServiceId, String> {
        self.register_extension_inner(config, id)
    }

    fn register_extension_inner(
        &mut self,
        config: ExtensionConfig,
        id: ServiceId,
    ) -> Result<ServiceId, String> {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let outbox = self.outbox_tx.clone();

        // Per-agent shutdown flag (node-wide shutdown fans out to
        // it) so the daemon can stop this extension individually. Install it
        // in the node map only after startup succeeds.
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let registered_name = config.name.clone();
        let activity = self.last_activity.clone();
        let invoke_routes = self.invoke_routes.clone();
        let agent_names = self.agent_names.clone();
        let proof_blobs = self.proof_blobs.clone();
        let proof_blobs_dir = self.proof_blobs_dir.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();
        let raft_fwd = RaftFwd {
            #[cfg(all(feature = "network", feature = "storage"))]
            network: self.shared_network.clone(),
            #[cfg(all(feature = "network", feature = "storage"))]
            hosts: self.raft_hosts.clone(),
        };

        let join = thread::spawn(move || {
            extension_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                agent_names,
                worker_shutdown,
                activity,
                proof_blobs,
                proof_blobs_dir,
                raft_fwd,
                startup_tx,
                #[cfg(feature = "network")]
                shared_network,
            )
        });

        match startup_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = join.join();
                return Err(error);
            }
            Err(_) => {
                let detail = match join.join() {
                    Ok(result) => result
                        .error
                        .unwrap_or_else(|| "extension worker exited during startup".into()),
                    Err(_) => "extension worker panicked during startup".into(),
                };
                return Err(detail);
            }
        }

        // Startup is now committed and acknowledged. Only at this point is
        // the extension discoverable or reachable through either route map.
        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);
        self.record_agent_name(id, registered_name.clone());
        self.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: registered_name,
                // Native extensions have no consistency tier; they relay
                // through explicit relay authority and stay network-reachable.
                consistency: None,
                network_reachable: true,
            },
        );
        self.install_agent_shutdown(id, shutdown);
        self.agents.push(AgentHandle { join: Some(join) });
        Ok(id)
    }

    /// Route messages until the node has been globally idle for the
    /// default duration (2 seconds). Shorthand for
    /// `run_until_idle(Duration::from_secs(2))`.
    pub fn run(&mut self) {
        self.run_until_idle(Duration::from_secs(2));
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn publish_ready_service_raft_roots(&mut self) {
        while let Ok(publish) = self.pending_service_root_ready_rx.try_recv() {
            publish(self);
            *self.last_activity.lock().unwrap() = Instant::now();
        }
        let mut index = 0;
        while index < self.pending_service_root_threads.len() {
            if self.pending_service_root_threads[index].is_finished() {
                let thread = self.pending_service_root_threads.swap_remove(index);
                let _ = thread.join();
            } else {
                index += 1;
            }
        }
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn has_pending_service_raft_roots(&self) -> bool {
        !self.pending_service_root_ids.lock().unwrap().is_empty()
    }

    /// Route messages until traffic — both outbox routing AND
    /// agent/worker dispatch — has been quiet for `threshold`,
    /// then signal shutdown to all threads.
    ///
    /// Unlike the previous "agents auto-exit on idle" heuristic,
    /// this is decided centrally: agents stay alive as long as the
    /// node hasn't told them to stop. That keeps cross-agent
    /// invoke peers reachable for the entire run, even when one
    /// side has nothing on its inbox at the moment.
    pub fn run_until_idle(&mut self, threshold: Duration) {
        *self.last_activity.lock().unwrap() = Instant::now();
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if !self.drive_clean_agent_owner() {
                break;
            }
            if self.local_agent_host_failed() {
                self.signal_node_shutdown();
                break;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            self.publish_ready_service_raft_roots();
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // If every agent has already exited (e.g.
                    // they all errored at startup), there's no
                    // point waiting out the threshold.
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    let all_done = all_done
                        && self
                            .local_agent_host
                            .as_ref()
                            .is_none_or(|host| !host.is_running());
                    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
                    let all_done = all_done
                        && self
                            .clean_agent_owner
                            .as_ref()
                            .is_none_or(|owner| !owner.is_running());
                    #[cfg(all(feature = "network", feature = "storage"))]
                    let all_done = all_done && !self.has_pending_service_raft_roots();
                    if all_done {
                        break;
                    }

                    let idle = self.last_activity.lock().unwrap().elapsed();
                    let idle = self
                        .local_agent_host
                        .as_ref()
                        .map_or(idle, |host| idle.min(host.idle_for()));
                    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
                    let idle = self
                        .clean_agent_owner
                        .as_ref()
                        .map_or(idle, |worker| idle.min(worker.idle_for()));
                    if idle >= threshold {
                        self.signal_node_shutdown();
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        self.signal_node_shutdown();
    }

    /// Run forever, only stopping when [`shutdown`](Self::shutdown)
    /// is called from another thread (e.g. a SIGTERM handler) or
    /// every agent has exited on its own.
    pub fn run_forever(&mut self) {
        self.run_forever_with(|_| {});
    }

    /// Like [`run_forever`](Self::run_forever), but invokes
    /// `on_tick` with `&mut self` on every loop pass — after each
    /// routed envelope and on each ~50 ms idle timeout — so the
    /// hook keeps firing under sustained envelope traffic. This is
    /// the only moment the embedder can get mutable access to a
    /// running node, so it's the hook for maintenance work that
    /// needs registration rights — e.g. spawning agents that were
    /// installed (or CRDT-synced into the registry) after boot.
    ///
    /// Contract:
    /// - The callback runs on the router thread with envelope
    ///   routing paused, and may fire many times per second under
    ///   traffic: rate-limit internally (a cheap elapsed check) and
    ///   keep the heavy path short.
    /// - Synchronous invokes are safe against PVM actors and extensions:
    ///   both route nested `ctx.ask` calls through `invoke_routes` directly.
    /// - The loop still exits when every agent thread has finished,
    ///   checked before the idle-arm callback: on a node with no
    ///   (live) agents the hook never fires, so it cannot be used
    ///   to bootstrap the first agent.
    pub fn run_forever_with(&mut self, mut on_tick: impl FnMut(&mut Self)) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if !self.drive_clean_agent_owner() {
                break;
            }
            if self.local_agent_host_failed() {
                self.signal_node_shutdown();
                break;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            self.publish_ready_service_raft_roots();
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                    on_tick(self);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    let all_done = all_done
                        && self
                            .local_agent_host
                            .as_ref()
                            .is_none_or(|host| !host.is_running());
                    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
                    let all_done = all_done
                        && self
                            .clean_agent_owner
                            .as_ref()
                            .is_none_or(|owner| !owner.is_running());
                    #[cfg(all(feature = "network", feature = "storage"))]
                    let all_done = all_done && !self.has_pending_service_raft_roots();
                    if all_done {
                        break;
                    }
                    on_tick(self);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // A raw shutdown handle only flips the node-wide atomic. Fan that
        // terminal state out before returning so Agent-native and legacy
        // workers cannot remain live in the gap before `collect` or Drop.
        self.signal_node_shutdown();
    }

    /// Trigger an explicit node-wide shutdown. Threads notice on their next
    /// iteration (≤ 50 ms) and exit cleanly. Safe to call from a signal handler
    /// or another thread.
    pub fn shutdown(&self) {
        self.signal_node_shutdown();
    }

    /// Set the node-wide shutdown flag AND fan it out to every per-agent flag
    ///. Agent threads poll their own flag, so the fan-out is
    /// what actually stops them on a node-wide shutdown; non-agent machinery
    /// (network bridge, sync ticker) still reads the node-wide flag directly.
    fn signal_node_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
        {
            self.clean_local_lifecycle_queue.close();
            if let Ok(mut exposed) = self.clean_agent_ingress_supervisor.write() {
                *exposed = None;
            }
            if let Some(owner) = self.clean_agent_owner.as_ref() {
                owner.request_shutdown();
            }
        }
        if let Some(host) = self.local_agent_host.as_ref() {
            host.request_shutdown();
        }
        if let Ok(map) = self.agent_shutdown.lock() {
            for flag in map.values() {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    fn drive_clean_agent_owner(&mut self) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            self.signal_node_shutdown();
            return false;
        }
        if self
            .clean_agent_owner
            .as_ref()
            .is_some_and(|worker| !worker.is_running())
        {
            self.signal_node_shutdown();
            return false;
        }
        true
    }

    fn local_agent_host_failed(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
            && self
                .local_agent_host
                .as_ref()
                .is_some_and(|host| !host.is_running())
    }

    /// Allocate (and register) this agent's own shutdown flag.
    /// Returned to the spawn site as the thread's `shutdown` signal; retained in
    /// [`Self::agent_shutdown`] so [`Self::stop_agent`] / a node-wide shutdown
    /// can flip it. Idempotent per id (re-registering returns a fresh flag).
    fn register_agent_shutdown(&mut self, id: ServiceId) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        self.install_agent_shutdown(id, flag.clone());
        flag
    }

    fn install_agent_shutdown(&mut self, id: ServiceId, flag: Arc<AtomicBool>) {
        if self
            .agent_shutdown
            .lock()
            .unwrap()
            .insert(id.0, flag.clone())
            .is_some()
        {
            // Two agents at the same full id.0 (a ~15-bit instance-name hash
            // collision under one node prefix; same root cause as the
            // `record_agent_name` collision WARN). The evicted flag is no
            // longer reachable from `signal_node_shutdown`'s fan-out, so a
            // transport agent left on the evicted flag could miss a node-wide
            // shutdown (its accept loop polls only this flag) — surface it.
            warn!(
                id = id.0,
                "register: shutdown-flag collision on service id; node-wide shutdown \
                 may not reach the evicted agent (rename one of the colliding instances)"
            );
        }
    }

    /// Stop a SINGLE agent by id without tearing down the node.
    /// Flips that agent's shutdown flag; its thread exits on the next poll
    /// (≤ 50 ms) — the generic lifecycle primitive behind `vosx <agent> stop`,
    /// uniform across actor / service / transport agents. Returns `false` when
    /// no agent is registered under `id`.
    pub fn stop_agent(&self, id: ServiceId) -> bool {
        match self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id.0).cloned())
        {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Whether an agent (actor, service, or transport) is registered or has a
    /// locally prepared Raft root awaiting voter promotion under `id` on this
    /// node. Stays `true` for agents
    /// that were stopped individually (`stop_agent`) — their slot
    /// is still taken, so re-registering at the same id would
    /// clobber routes. The cheap idempotency probe for embedder
    /// spawn-reconcile loops.
    pub fn has_agent(&self, id: ServiceId) -> bool {
        let registered = self
            .agent_info
            .read()
            .map(|m| m.contains_key(&id.0))
            .unwrap_or(false);
        #[cfg(all(feature = "network", feature = "storage"))]
        let registered = registered
            || self
                .pending_service_root_ids
                .lock()
                .unwrap()
                .contains(&id.0);
        registered
    }

    /// Describe a SINGLE agent by id: a JSON snapshot of its
    /// registered metadata + live running flag, backing `vosx <agent> describe`.
    /// Generic across actor / service / transport agents (the in-process twin of
    /// the `__describe` host interceptor). `None` when no agent is registered
    /// under `id`.
    pub fn describe_agent(&self, id: ServiceId) -> Option<String> {
        let info = self.agent_info.read().ok()?.get(&id.0).cloned()?;
        let running = self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id.0).map(|f| !f.load(Ordering::Relaxed)))
            .unwrap_or(true)
            && !self.shutdown.load(Ordering::Relaxed);
        Some(describe_agent_json(id.0, &info, running))
    }

    /// Clone of the attached network, if any. Lets external code
    /// (tests, monitoring, host-side bootstraps) inspect peer
    /// state — `peer_for_prefix`, `connected_peers`, etc. —
    /// without taking the network out of the node's ownership.
    /// Returns `None` until [`attach_network`](Self::attach_network)
    /// has run.
    #[cfg(feature = "network")]
    pub fn network(&self) -> Option<Arc<crate::network::Network>> {
        self.shared_network.lock().ok().and_then(|g| g.clone())
    }

    /// Clone of the shutdown signal. Set to `true` from any thread
    /// to wind the node down. Useful when the node has been moved
    /// into a [`run_forever`](Self::run_forever) thread.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Returns a thread-safe handle that can synchronously invoke
    /// any **local** service registered on this node. Background
    /// tasks (e.g. vosx's auto-heartbeat) take this handle before
    /// [`run_forever`](Self::run_forever) blocks the main thread,
    /// then keep calling into the node from a side thread.
    ///
    /// Cross-node invokes aren't supported through this handle —
    /// it doesn't carry the network reference. Use [`invoke`](Self::invoke)
    /// from the owning thread for that.
    pub fn invoke_handle(&self) -> InvokeHandle {
        InvokeHandle {
            invoke_routes: self.invoke_routes.clone(),
            shutdown: self.shutdown.clone(),
        }
    }

    /// Returns the protocol-neutral handle used by built-in ingress adapters.
    /// Unlike [`InvokeHandle`], application calls made through this handle
    /// require an explicit authenticated member subject and retain it across
    /// Raft leader redirects.
    pub fn ingress_handle(&self) -> IngressHandle {
        IngressHandle {
            invoke_routes: self.invoke_routes.clone(),
            service_actor_routes: self.service_actor_routes.clone(),
            service_invocation_seed: self.service_invocation_seed,
            service_invocation_ordinal: self.service_invocation_ordinal.clone(),
            agent_names: self.agent_names.clone(),
            shutdown: self.shutdown.clone(),
            #[cfg(feature = "network")]
            shared_network: self.shared_network.clone(),
            #[cfg(feature = "ssh-ingress")]
            ingress_node_attester: self.ingress_node_attester.clone(),
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_agent_supervisor: self.clean_agent_ingress_supervisor.clone(),
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_agent_recovering: self.clean_agent_recovering.clone(),
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            clean_local_lifecycle_queue: self.clean_local_lifecycle_queue.clone(),
        }
    }

    /// Configure the daemon's SSH ingress attester exactly once. The raw
    /// callback remains private; callers receive only the typed authority-query
    /// operation on [`IngressHandle`].
    #[cfg(feature = "ssh-ingress")]
    pub fn set_ingress_node_attester<F>(
        &mut self,
        node: crate::agent::sdk::NodeId,
        signer: F,
    ) -> Result<(), IngressNodeAttestationError>
    where
        F: Fn(&[u8]) -> Option<[u8; 64]> + Send + Sync + 'static,
    {
        if node == crate::agent::sdk::NodeId::ZERO {
            return Err(IngressNodeAttestationError::InvalidNode);
        }
        if self.ingress_node_attester.is_some() {
            return Err(IngressNodeAttestationError::AlreadyConfigured);
        }
        self.ingress_node_attester = Some(IngressNodeAttester {
            node,
            signer: Arc::new(signer),
        });
        Ok(())
    }

    /// Bind one built-in HTTP ingress listener. Merely compiling the feature
    /// never opens a socket; callers must provide explicit typed config.
    #[cfg(feature = "http-ingress")]
    pub fn add_http_ingress(
        &mut self,
        config: crate::ingress::HttpIngressConfig,
    ) -> Result<(), crate::ingress::HttpIngressError> {
        let thread = crate::ingress::start(config, self.ingress_handle())?;
        self.ingress_threads.push(thread);
        Ok(())
    }

    /// Bind one built-in SSH space-shell listener.
    #[cfg(feature = "ssh-ingress")]
    pub fn add_ssh_ingress(
        &mut self,
        config: crate::ssh_ingress::SshIngressConfig,
    ) -> Result<(), crate::ssh_ingress::SshIngressError> {
        let thread = crate::ssh_ingress::start(config, self.ingress_handle())?;
        self.ingress_threads.push(thread);
        Ok(())
    }

    /// Clone of the outbox sender. Pushing an [`Envelope`] here
    /// runs it through [`route`](Self::route) — the same path
    /// agent threads use for outgoing transfers — so addresses
    /// targeting other nodes get forwarded over the network when
    /// one is attached. Intended for host-side bootstraps and
    /// tests that need to inject traffic from outside the agent
    /// system.
    pub fn outbox_sender(&self) -> mpsc::Sender<Envelope> {
        self.outbox_tx.clone()
    }

    /// Install a "ghost" route under a fresh ServiceId: every
    /// envelope routed to that ID is delivered to the returned
    /// channel instead of an agent. Used by integration tests to
    /// observe what crosses the routing layer; not part of the
    /// production API.
    #[cfg(test)]
    pub(crate) fn install_inspector(&mut self) -> (ServiceId, mpsc::Receiver<Envelope>) {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        self.routes.insert(id.0, tx);
        (id, rx)
    }

    /// Register a `(replication_id → redb path)` pair directly in
    /// the CRDT replica map and spin up the matching sync ticker.
    /// Used by tests that want to verify the sync layer without
    /// spinning up a real PVM agent. No notifier is wired because
    /// no agent thread is consuming.
    #[cfg(all(test, feature = "network", feature = "storage"))]
    pub(crate) fn install_test_replica(
        &mut self,
        rep_id: [u8; 32],
        db_path: &std::path::Path,
    ) -> ReplicaSlot {
        self.install_test_replica_named(rep_id, db_path, "")
    }

    /// Like [`Self::install_test_replica`] but tags the replica with an
    /// instance `name` so the sync-serve membership gate can be
    /// exercised (a `msg-*` name is private; anything else serves
    /// openly).
    #[cfg(all(test, feature = "network", feature = "storage"))]
    pub(crate) fn install_test_replica_named(
        &mut self,
        rep_id: [u8; 32],
        db_path: &std::path::Path,
        name: &str,
    ) -> ReplicaSlot {
        let slot = ReplicaSlot {
            db: Arc::new(redb::Database::create(db_path).expect("create db")),
            commit_lock: Arc::new(Mutex::new(())),
            name: name.to_string(),
            node_validator: None,
        };
        self.crdt_replicas
            .lock()
            .unwrap()
            .insert(rep_id, slot.clone());
        self.spawn_sync_thread(rep_id, slot.clone(), None);
        slot
    }

    /// Spawn the per-replica sync ticker. Detached: exits via the
    /// shared shutdown flag (set on `collect`/`shutdown`) or when
    /// the network/db Arcs die. `notifier` (when present) is
    /// pinged after a non-empty merge so the agent thread can
    /// run `soft_restart_crdt` to pick up the new state.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn spawn_sync_thread(
        &mut self,
        rep_id: [u8; 32],
        slot: ReplicaSlot,
        notifier: Option<mpsc::Sender<()>>,
    ) {
        let shared_network = self.shared_network.clone();
        let shutdown = self.shutdown.clone();
        let join =
            thread::spawn(move || sync_loop(rep_id, shared_network, slot, shutdown, notifier));
        self.sync_threads.push(join);
    }

    /// Install a synchronous-invoke responder under a fresh
    /// ServiceId. The handler runs on a helper thread; each
    /// inbound `InvokeRequest` is fed its `msg` bytes and the
    /// returned `Vec<u8>` is sent back as the reply.
    #[cfg(test)]
    pub(crate) fn install_invoke_responder<F>(&mut self, mut handler: F) -> ServiceId
    where
        F: FnMut(Vec<u8>) -> Vec<u8> + Send + 'static,
    {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        self.invoke_routes.lock().unwrap().insert(id.0, tx);
        thread::spawn(move || {
            for req in rx {
                let reply = handler(req.msg);
                // Test responders never yield — pack as DONE so
                // the reply parses as `InvokeResult::Done` on the
                // caller side, matching real worker/agent shape.
                let envelope = encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply);
                let _ = req.reply.send(envelope);
            }
        });
        id
    }

    /// Synchronously invoke a registered service from outside the
    /// PVM — for tests, host-side bootstraps, and any code path
    /// where you want to ask an agent or worker without first
    /// spinning up another PVM agent to do it.
    ///
    /// Returns the raw rkyv-encoded reply bytes, or `None` if the
    /// target isn't registered, the channel is disconnected, the
    /// reply exceeds the producer cap, or the call times out.
    /// Default timeout is 10 seconds; use
    /// [`invoke_with_timeout`](Self::invoke_with_timeout) for
    /// finer control.
    pub fn invoke(&self, target: ServiceId, msg: Vec<u8>) -> Option<Vec<u8>> {
        self.invoke_with_timeout(target, msg, Duration::from_secs(10))
    }

    /// Invoke one canonical service actor through its registered root service.
    /// The node allocates a boot-unique invocation identity and preserves the
    /// full ActorId until guest Refine and Accumulate have both accepted it.
    pub fn invoke_actor(
        &self,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
    ) -> Result<Vec<u8>, crate::actors::client::ClientError> {
        self.invoke_actor_wire(target, arguments, false)
    }

    /// Invoke an attested service actor method and return the proof package that
    /// guest Accumulate committed beside the exact reply. Roots registered
    /// without an explicit producer reject this capability.
    pub fn invoke_actor_attested(
        &self,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
    ) -> Result<crate::actors::client::AttestedInvocationResult, crate::actors::client::ClientError>
    {
        use crate::{Decode, service::ServiceWire};

        let wire = self.invoke_actor_wire(target, arguments, true)?;
        let result = crate::service::RootTreeAttestedResult::decode(&wire)
            .map_err(|_| crate::actors::client::ClientError::Decode)?;
        let value = <crate::value::Value as Decode>::try_decode(&result.reply)
            .ok_or(crate::actors::client::ClientError::Decode)?;
        Ok(crate::actors::client::AttestedInvocationResult {
            value,
            producer_name: result.attestation.producer_name,
            producer: result.attestation.producer,
            statement: result.attestation.statement,
            trace: result.attestation.proof.trace,
            proof: result.proof,
        })
    }

    fn invoke_actor_wire(
        &self,
        target: crate::service::ActorId,
        arguments: Vec<u8>,
        proof_requested: bool,
    ) -> Result<Vec<u8>, crate::actors::client::ClientError> {
        use crate::Decode;

        if arguments.first() != Some(&crate::value::TAG_DYNAMIC) {
            return Err(crate::actors::client::ClientError::Decode);
        }
        let message = <crate::value::Msg as Decode>::try_decode(&arguments[1..])
            .ok_or(crate::actors::client::ClientError::Decode)?;
        let binding = self
            .service_actor_routes
            .read()
            .map_err(|_| crate::actors::client::ClientError::Unreachable)?
            .get(&target)
            .cloned()
            .ok_or(crate::actors::client::ClientError::NotFound)?;
        let route = binding.route;
        let deadline = Instant::now()
            .checked_add(binding.invoke_timeout)
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
        let tx = self
            .invoke_routes
            .lock()
            .map_err(|_| crate::actors::client::ClientError::Unreachable)?
            .get(&route)
            .cloned()
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
        let ordinal = self
            .service_invocation_ordinal
            .fetch_add(1, Ordering::Relaxed);
        let mut nonce = Vec::with_capacity(72);
        nonce.extend_from_slice(&self.service_invocation_seed);
        nonce.extend_from_slice(&ordinal.to_le_bytes());
        nonce.extend_from_slice(&target.0);
        let ingress = crate::service::RootTreeInvocation {
            invocation: crate::service::InvocationId::derive(
                b"vos/node-root-invocation/service",
                &nonce,
            ),
            target,
            method: message.name,
            arguments,
            proof_requested,
        };
        let ingress_wire = crate::service::ServiceWire::encode(&ingress);
        let reply_rx = send_service_system_ingress(&tx, &ingress_wire)?;
        // Proof production is synchronous and currently has no cancellation
        // contract. Once an attested invocation is handed to the root driver,
        // reporting a local timeout would allow its Apply to commit after the
        // caller observed failure. Await its terminal disposition instead;
        // ordinary work retains the bounded route timeout.
        let envelope = receive_service_invocation_reply(&reply_rx, proof_requested, deadline)?;
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(redirect) = decode_service_raft_redirect(&envelope) {
            let network = self
                .shared_network
                .lock()
                .map_err(|_| crate::actors::client::ClientError::Unreachable)?
                .clone()
                .ok_or(crate::actors::client::ClientError::Unreachable)?;

            if proof_requested {
                let local_route = tx.clone();
                let replication_id = binding.replication_id;
                let remote_binding = binding.clone();
                return receive_service_attested_with_exact_redrive(
                    &ingress_wire,
                    redirect,
                    |redirect, ingress| {
                        let Some(replication_id) = replication_id else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        let Some(status) = network.local_raft_status(&replication_id) else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        let Some(deadline) =
                            Instant::now().checked_add(remote_binding.invoke_timeout)
                        else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        send_service_raft_invoke_exact(
                            &network,
                            &self.invoke_routes,
                            &remote_binding,
                            status,
                            redirect.leader_prefix,
                            redirect.origin,
                            true,
                            false,
                            false,
                            ingress,
                            deadline,
                        )
                        .map_or(
                            AttestedRedriveAttempt::Ambiguous,
                            AttestedRedriveAttempt::Reply,
                        )
                    },
                    |ingress| {
                        let Ok(reply) = send_service_system_ingress(&local_route, ingress) else {
                            return AttestedRedriveAttempt::NotSent;
                        };
                        match reply.recv() {
                            Ok(envelope) => AttestedRedriveAttempt::Reply(envelope),
                            Err(_) => AttestedRedriveAttempt::Ambiguous,
                        }
                    },
                    || std::thread::sleep(Duration::from_millis(100)),
                );
            }

            let replication_id = binding
                .replication_id
                .ok_or(crate::actors::client::ClientError::Unreachable)?;
            let status = network
                .local_raft_status(&replication_id)
                .ok_or(crate::actors::client::ClientError::Unreachable)?;
            let leader_envelope = send_service_raft_invoke_exact(
                &network,
                &self.invoke_routes,
                &binding,
                status,
                redirect.leader_prefix,
                redirect.origin,
                true,
                false,
                false,
                &ingress_wire,
                deadline,
            )
            .ok_or(crate::actors::client::ClientError::Unreachable)?;
            return decode_host_invoke_envelope(&leader_envelope);
        }
        decode_host_invoke_envelope(&envelope)
    }

    /// Like [`invoke`](Self::invoke) but with an explicit timeout.
    ///
    /// Lookup order:
    ///
    /// 1. Local invoke route (any agent or worker on this node).
    /// 2. Cross-node via the attached network: when the target's
    ///    `node_prefix` doesn't match this node and a peer with
    ///    that prefix has completed the Hello handshake, the
    ///    invoke is forwarded over libp2p.
    ///
    /// Returns `None` if neither path resolves the target, or if
    /// the call times out / the channel disconnects.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let deadline = Instant::now().checked_add(timeout)?;
        // 1. Local. Same fallback `dispatch_invoke` uses: when
        //    `target` carries this node's prefix but the agent
        //    was registered as unscoped (`ServiceId(0, local_id)`),
        //    retry with the prefix stripped. The well-known
        //    registry registers at `ServiceId::REGISTRY` (= 0),
        //    so a local invoke from an in-process Ref pointed
        //    at `(self.node_prefix, 0)` wouldn't find it
        //    otherwise.
        let local_tx = {
            let map = self.invoke_routes.lock().ok()?;
            let direct = map.get(&target.0).cloned();
            if direct.is_some() {
                direct
            } else if target.is_on_node(self.node_prefix) {
                map.get(&(target.0 & 0xFFFF)).cloned()
            } else {
                None
            }
        };
        if let Some(tx) = local_tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                // Host-side `VosNode::invoke` entry point.
                // `Caller::System` is the right variant for
                // embedder-originated calls (test harnesses, the
                // `vosx space up` bootstrap admin grant, etc.).
                // External peers can't synthesise this variant
                // — libp2p inbounds always arrive as
                // `Caller::Peer` via `dispatch_invoke`.
                caller: crate::actors::Caller::System,
                space_role: None,
                actor_local_role: None,
                #[cfg(all(feature = "network", feature = "storage"))]
                delegated_origin: None,
                role_authority_request: false,
                root_upgrade_request: false,
                invocation_id: None,
                native_call: None,
                msg: msg.clone(),
                reply: ReplyChannel::Sync(reply_tx),
                chain: Vec::new(),
            })
            .ok()?;
            // Cross-thread channel now carries the full invoke
            // envelope (status + state + reply); host callers
            // don't care about YIELDED/DONE so unwrap to just
            // reply bytes.
            let envelope = reply_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()?;
            #[cfg(all(feature = "network", feature = "storage"))]
            if let Some(redirect) = decode_service_raft_redirect(&envelope) {
                let net = self.shared_network.lock().ok().and_then(|g| g.clone())?;
                let binding = self
                    .service_actor_routes
                    .read()
                    .ok()?
                    .values()
                    .find(|route| {
                        route.consistency == crate::service::ConsistencyMode::Raft
                            && route.authenticated_peer.is_none()
                            && (route.route == target.0
                                || (route.route & 0xFFFF) == target.local_id() as u32)
                    })
                    .cloned()?;
                let replication_id = binding.replication_id?;
                let status = net.local_raft_status(&replication_id)?;
                return send_service_raft_invoke_exact(
                    &net,
                    &self.invoke_routes,
                    &binding,
                    status,
                    redirect.leader_prefix,
                    redirect.origin,
                    false,
                    false,
                    redirect.root_upgrade_request,
                    &msg,
                    deadline,
                );
            }
            return unwrap_invoke_envelope(&envelope);
        }

        // 2. Cross-node fallback.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(self.node_prefix) && !target.is_local() {
                let net = self.shared_network.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net
                    && let Some(peer) = net.peer_for_prefix(target.node_prefix())
                {
                    // `from = 0` because this is host-side; it
                    // never participates in chain detection.
                    let reply_rx =
                        net.send_invoke(peer, ServiceId::REGISTRY.0, target.0, Vec::new(), msg);
                    // Daemon's `dispatch_invoke` already strips
                    // the envelope back to raw reply bytes, so
                    // we just forward them.
                    return reply_rx
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .ok();
                }
            }
        }

        None
    }

    /// Route a single envelope to its destination.
    #[cfg_attr(not(all(feature = "network", feature = "storage")), allow(unused_mut))]
    fn route(&self, mut envelope: Envelope) {
        // Locally originated Raft transport follows the replication group's
        // current leader, never the replica which happened to populate the
        // actor-route cache. This applies symmetrically to deliveries, replies,
        // and their acknowledgements. Inbound frames retain their exact Noise
        // peer and are authenticated by the bridge + root handler instead.
        #[cfg(all(feature = "network", feature = "storage"))]
        if envelope.payload.starts_with(b"VRTW")
            && envelope.authenticated_source_peer.is_none()
            && let Some(binding) =
                service_transport_destination_route(&self.service_actor_routes, &envelope.payload)
            && binding.consistency == crate::service::ConsistencyMode::Raft
        {
            let network = self.shared_network.lock().ok().and_then(|g| g.clone());
            let local_tx = (binding.authenticated_peer.is_none())
                .then(|| self.routes.get(&binding.route).cloned())
                .flatten();

            // Networkless single-voter roots are fully supported. Once a
            // network handler exists, even a fresh local `Leader` role is not
            // enough: an isolated former leader can retain that role without
            // quorum. Route through bounded multi-voter discovery so a newer
            // term elsewhere wins before any local dispatch.
            let local_is_current_leader = local_tx.is_some()
                && network.as_ref().is_none_or(|network| {
                    binding
                        .replication_id
                        .is_none_or(|id| !network.has_local_raft_handler(&id))
                });
            if local_is_current_leader {
                envelope.to = ServiceId(binding.route);
                let _ = local_tx.expect("checked above").send(envelope);
                return;
            }

            let Some(network) = network else {
                warn!(target = %envelope.to, "node: no local Raft root or network leader route");
                return;
            };
            self.route_service_raft_transport_async(envelope, binding, network, local_tx);
            return;
        }

        let target = envelope.to;

        // Canonical service transport may deliberately target a remote PeerId
        // whose derived 16-bit prefix collides with this node. An explicit
        // trusted destination therefore wins over the lossy local-prefix
        // classification. Inbound frames carry only `authenticated_source_peer`
        // and continue through ordinary local delivery below.
        if envelope.payload.starts_with(b"VRTW")
            && let Some(_peer_bytes) = envelope.destination_peer.as_deref()
        {
            #[cfg(feature = "network")]
            {
                let Some(peer) = libp2p::PeerId::from_bytes(_peer_bytes).ok() else {
                    warn!(%target, "node: service root envelope carried an invalid destination peer");
                    return;
                };
                use crate::service::ServiceWire;
                let crdt_service = crate::service::RootTreeTransport::decode(&envelope.payload)
                    .ok()
                    .and_then(|transport| match transport {
                        crate::service::RootTreeTransport::CrdtSyncChunk { envelope, .. } => {
                            Some(envelope.service)
                        }
                        crate::service::RootTreeTransport::CrdtSyncAccepted { service, .. } => {
                            Some(service)
                        }
                        _ => None,
                    });
                let bound = self.service_actor_routes.read().ok().is_some_and(|routes| {
                    routes.values().any(|route| match crdt_service.as_ref() {
                        Some(service) => {
                            route.service == *service
                                && route.consistency == crate::service::ConsistencyMode::Crdt
                                && route.authenticated_peer.is_none()
                                && ServiceId(route.route).local_id() == target.local_id()
                        }
                        None => {
                            route.route == target.0
                                && matches!(
                                    route.consistency,
                                    crate::service::ConsistencyMode::Local
                                        | crate::service::ConsistencyMode::Raft
                                        | crate::service::ConsistencyMode::Crdt
                                )
                                && route.authenticated_peer.as_deref() == Some(_peer_bytes)
                        }
                    })
                });
                if !bound {
                    warn!(%target, %peer, "node: service root envelope peer is not bound to its route");
                    return;
                }
                let net = self.shared_network.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net {
                    net.send_tell(peer, envelope.from.0, envelope.to.0, envelope.payload);
                } else {
                    warn!(%target, %peer, "node: no network layer for exact service destination");
                }
            }
            #[cfg(not(feature = "network"))]
            warn!(%target, "node: no network support for exact service destination");
            return;
        }

        // Local delivery: prefix matches or target is unscoped (prefix 0)
        if target.is_on_node(self.node_prefix) || target.is_local() {
            if let Some(tx) = self.routes.get(&target.0) {
                let _ = tx.send(envelope);
            } else {
                warn!(%target, "node: no route for target, dropping");
            }
            return;
        }

        // Remote delivery via the network (if attached). The
        // target's high 16 bits select the peer; if we haven't
        // seen that prefix yet (no Hello received), the envelope
        // is dropped with a warn — VOS has no store-and-forward
        // semantics today.
        #[cfg(feature = "network")]
        {
            let net = self.shared_network.lock().ok().and_then(|g| g.clone());
            if let Some(net) = net {
                if envelope.payload.starts_with(b"VRTW") {
                    warn!(%target, "node: remote service envelope omitted its exact destination peer");
                    return;
                }
                let prefix = target.node_prefix();
                if let Some(peer) = net.peer_for_prefix(prefix) {
                    net.send_tell(peer, envelope.from.0, envelope.to.0, envelope.payload);
                    return;
                }
                warn!(
                    %target,
                    prefix = format!("{prefix:#06x}"),
                    "node: no peer known for prefix; dropping remote envelope",
                );
                return;
            }
        }

        warn!(%target, "node: no network layer, dropping remote target");
    }

    /// Resolve and dispatch one durable Raft transport envelope without ever
    /// blocking the global router. One worker is active per destination root;
    /// duplicate 250 ms redrives are coalesced, successful leaders are cached
    /// briefly, and failures back off before durable state retries them.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn route_service_raft_transport_async(
        &self,
        envelope: Envelope,
        binding: ActorRoute,
        network: Arc<crate::network::Network>,
        local_tx: Option<mpsc::Sender<Envelope>>,
    ) {
        let Some(replication_id) = binding.replication_id else {
            warn!(target = %envelope.to, "node: Raft transport route omitted its replication identity");
            return;
        };
        let key = RaftTransportResolutionKey {
            replication_id,
            local_id: ServiceId(binding.route).local_id(),
        };
        let now = Instant::now();
        let (deadline, pending_until) = service_raft_transport_resolution_deadlines(now);
        let mut ownership_generation = None;
        let mut resolution_candidate_cursor = None;
        let cached = {
            let Ok(mut resolutions) = self.service_raft_transport_resolutions.lock() else {
                return;
            };
            let candidate_cursor = resolutions
                .get(&key)
                .map(RaftTransportResolution::candidate_cursor)
                .unwrap_or(0);
            match resolutions.get(&key).cloned() {
                Some(RaftTransportResolution::Resolved {
                    peer, route, until, ..
                }) if until > now => Some((peer, route)),
                Some(RaftTransportResolution::Pending { until, .. }) if until > now => return,
                Some(RaftTransportResolution::Backoff { until, .. }) if until > now => return,
                _ => {
                    let generation = self
                        .service_raft_transport_ownership_generation
                        .fetch_add(1, Ordering::Relaxed);
                    ownership_generation = Some(generation);
                    resolution_candidate_cursor = Some(candidate_cursor);
                    resolutions.insert(
                        key,
                        RaftTransportResolution::Pending {
                            generation,
                            candidate_cursor,
                            until: pending_until,
                        },
                    );
                    None
                }
            }
        };

        if let Some((peer, route)) = cached {
            dispatch_resolved_service_raft_transport(&network, local_tx, peer, route, envelope);
            return;
        }
        let Some(ownership_generation) = ownership_generation else {
            return;
        };
        let Some(resolution_candidate_cursor) = resolution_candidate_cursor else {
            return;
        };

        let resolutions = self.service_raft_transport_resolutions.clone();
        let invoke_routes = self.invoke_routes.clone();
        let shutdown = self.shutdown.clone();
        thread::spawn(move || {
            let (resolved, next_candidate_cursor) = resolve_service_raft_leader_route_before(
                &binding,
                &network,
                &invoke_routes,
                deadline,
                resolution_candidate_cursor,
            );
            if shutdown.load(Ordering::Relaxed) {
                if let Ok(mut entries) = resolutions.lock() {
                    entries.remove(&key);
                }
                return;
            }
            let now = Instant::now();
            let owns_resolution = if let Ok(mut entries) = resolutions.lock() {
                if !matches!(
                    entries.get(&key),
                    Some(RaftTransportResolution::Pending { generation, candidate_cursor, until })
                        if *generation == ownership_generation
                            && *candidate_cursor == resolution_candidate_cursor
                            && *until == pending_until
                ) {
                    false
                } else {
                    match resolved.as_ref() {
                        Some((peer, route)) => {
                            entries.insert(
                                key,
                                RaftTransportResolution::Resolved {
                                    peer: *peer,
                                    route: *route,
                                    candidate_cursor: next_candidate_cursor,
                                    until: now + SERVICE_RAFT_TRANSPORT_LEADER_CACHE_TTL,
                                },
                            );
                        }
                        None => {
                            entries.insert(
                                key,
                                RaftTransportResolution::Backoff {
                                    candidate_cursor: next_candidate_cursor,
                                    until: now + SERVICE_RAFT_TRANSPORT_RETRY_BACKOFF,
                                },
                            );
                        }
                    }
                    true
                }
            } else {
                false
            };
            if !owns_resolution {
                return;
            }
            if let Some((peer, route)) = resolved {
                dispatch_resolved_service_raft_transport(&network, local_tx, peer, route, envelope);
            } else {
                warn!(target = %envelope.to, "node: no authenticated leader for Raft service transport");
            }
        });
    }

    /// Collect results from all agent threads. Forces shutdown if
    /// it hasn't already been requested, so callers don't have to
    /// remember the order.
    ///
    /// Also joins the per-replica sync threads. Without this,
    /// they outlive the node and keep `Arc<redb::Database>`
    /// references live, blocking any subsequent
    /// `redb::Database::create` against the same file with
    /// "Database already open. Cannot acquire lock." Restart
    /// scenarios depend on this join happening.
    pub fn collect(self) -> Vec<AgentResult> {
        let (results, agent_host_error) = self.collect_with_agent_host_status();
        if let Some(error) = agent_host_error {
            warn!(%error, "node: Local Agent host did not shut down cleanly");
        }
        results
    }

    /// Checked shutdown for Agent-native daemon owners.
    ///
    /// Unlike [`Self::collect`], an unexpected Local Agent-host worker panic
    /// is returned to the process boundary instead of being reduced to a log
    /// line. Legacy callers retain their existing vector result while the
    /// sealed production Agent adapter must use this method.
    pub fn collect_checked(self) -> Result<Vec<AgentResult>, crate::agent::host::AgentHostError> {
        let (results, agent_host_error) = self.collect_with_agent_host_status();
        match agent_host_error {
            Some(error) => Err(error),
            None => Ok(results),
        }
    }

    fn collect_with_agent_host_status(
        mut self,
    ) -> (Vec<AgentResult>, Option<crate::agent::host::AgentHostError>) {
        // Fan the node-wide shutdown out to every per-agent flag
        // so agent threads polling their OWN flag exit cleanly.
        self.signal_node_shutdown();
        #[cfg(any(feature = "http-ingress", feature = "ssh-ingress"))]
        for thread in self.ingress_threads.drain(..) {
            let _ = thread.join();
        }
        let mut agent_host_error = self
            .local_agent_host
            .take()
            .and_then(|host| host.shutdown().err());
        #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
        {
            let shutdown_error = self
                .clean_agent_owner
                .take()
                .and_then(|owner| owner.shutdown_and_join().err());
            if let Some(error) = shutdown_error {
                warn!(%error, "node: clean Agent production owner did not shut down cleanly");
                agent_host_error.get_or_insert(crate::agent::host::AgentHostError::Unavailable);
            }
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        {
            for thread in self.pending_service_root_threads.drain(..) {
                let _ = thread.join();
            }
            // A promotion may have completed immediately before shutdown and
            // queued its publication closure. Execute it under the shutdown
            // flag so it unregisters the prepared Raft handler instead of
            // leaving it attached to a separately-owned Network.
            self.publish_ready_service_raft_roots();
        }
        let (detached_outbox, _) = mpsc::channel();
        drop(core::mem::replace(&mut self.outbox_tx, detached_outbox));
        drop(core::mem::take(&mut self.routes)); // disconnect agent inboxes
        // Drain the invoke routes too so threads' invoke_rx
        // disconnects when the node is winding down.
        self.invoke_routes.lock().unwrap().clear();
        drop(core::mem::replace(
            &mut self.invoke_routes,
            Arc::new(Mutex::new(HashMap::new())),
        )); // drop our reference so threads' Arc count drops

        // Drop the replica registry so the sync threads' last
        // reference to each `Arc<redb::Database>` is the one
        // they hold themselves — once they exit, the underlying
        // file is unlocked.
        #[cfg(all(feature = "network", feature = "storage"))]
        {
            self.crdt_replicas.lock().unwrap().clear();
        }

        let agent_results: Vec<AgentResult> = self
            .agents
            .iter_mut()
            .filter_map(|h| h.join.take().and_then(|j| j.join().ok()))
            .collect();

        // Sync threads poll `shutdown` every SYNC_INTERVAL and
        // exit on the next tick, so this is a bounded wait.
        #[cfg(all(feature = "network", feature = "storage"))]
        for h in self.sync_threads.drain(..) {
            let _ = h.join();
        }

        (agent_results, agent_host_error)
    }
}

impl Default for VosNode {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VosNode {
    fn drop(&mut self) {
        // Startup may fail after a listener or worker has been spawned but
        // before the caller can reach `collect`. Never leave detached host
        // infrastructure running merely because construction returned early.
        self.signal_node_shutdown();
    }
}

fn service_root_origin(
    caller: &crate::actors::Caller,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
) -> Option<crate::service::Origin> {
    match caller {
        crate::actors::Caller::Unauthenticated => Some(crate::service::Origin::Anonymous),
        crate::actors::Caller::System => Some(crate::service::Origin::System),
        crate::actors::Caller::Peer(peer) => Some(crate::service::Origin::Member(
            crate::actors::context::authenticated_peer_subject(peer),
        )),
        crate::actors::Caller::Member(subject) => Some(crate::service::Origin::Member(*subject)),
        crate::actors::Caller::Actor(route) => actor_routes
            .read()
            .ok()?
            .iter()
            .find_map(|(actor, candidate)| (candidate.route == route.0).then_some(*actor))
            .map(crate::service::Origin::Actor),
    }
}

fn service_wall_timeslot() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Restore the node-wide allocator strictly above one service's committed
/// admission floor. Registration calls this before publishing any route, and
/// repeats it for every opened root, so the shared counter starts above the
/// greatest durable high-water on the node.
fn restore_service_logical_timeslot(
    clock: &AtomicU64,
    committed_high_water: u64,
) -> Result<(), NodeRegistrationError> {
    let next = committed_high_water
        .checked_add(1)
        .ok_or(NodeRegistrationError::LogicalTimeslotExhausted)?;
    clock.fetch_max(next, Ordering::Relaxed);
    Ok(())
}

/// Restore the node allocator from the service image currently visible after
/// catch-up. A Raft follower may legitimately have no header until genesis is
/// committed; every other root must already be installed at registration.
fn restore_service_root_logical_timeslot<B>(
    service: &crate::service::LocalRootTreeService<B>,
    clock: &AtomicU64,
) -> Result<bool, NodeRegistrationError>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    match service
        .store()
        .header()
        .map_err(|_| NodeRegistrationError::CorruptServiceStore)?
    {
        Some(header) => {
            restore_service_logical_timeslot(clock, header.admission_timeslot_high_water)?;
            Ok(true)
        }
        None if service.consistency() == crate::service::ConsistencyMode::Raft => Ok(false),
        None => Err(NodeRegistrationError::CorruptServiceStore),
    }
}

/// Allocate a trusted, monotone local admission slot. The durable service
/// high-water makes restart safe; wall time supplies a useful initial floor,
/// and compare/exchange keeps concurrent service threads in one node-wide
/// order even when the wall clock has not advanced.
fn next_service_logical_timeslot(clock: &AtomicU64) -> u64 {
    let wall = service_wall_timeslot();
    let mut observed = clock.load(Ordering::Relaxed);
    loop {
        let admitted = observed.max(wall);
        let next = admitted.saturating_add(1);
        match clock.compare_exchange_weak(observed, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return admitted,
            Err(actual) => observed = actual,
        }
    }
}

fn send_service_status(reply: ReplyChannel, status: u8, id: ServiceId) {
    let _ = send_reply_capped(reply, encode_invoke_envelope(status, &[], &[]), id);
}

#[cfg(all(feature = "storage", feature = "network"))]
const SERVICE_RAFT_REDIRECT_STATUS: u8 = 0xFE;

#[cfg(all(feature = "storage", feature = "network"))]
const SERVICE_RAFT_DELEGATION_MAGIC: [u8; 4] = *b"VRDW";

#[cfg(all(feature = "storage", feature = "network"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RaftRedirect {
    leader_prefix: u16,
    origin: crate::service::Origin,
    root_upgrade_request: bool,
}

#[cfg(all(feature = "storage", feature = "network"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RaftDelegatedIngress {
    origin: crate::service::Origin,
    /// Return the complete status/state/reply envelope to typed host callers.
    /// Actor and extension forwarding returns only the actor reply.
    preserve_envelope: bool,
    /// Host-private protocol marker forwarded only after the source peer has
    /// been authenticated as a voter of this exact root's Raft group.
    role_authority_request: bool,
    root_upgrade_request: bool,
    ingress: Vec<u8>,
}

#[cfg(all(feature = "storage", feature = "network"))]
fn encode_service_origin(wire: &mut Vec<u8>, origin: crate::service::Origin) {
    match origin {
        crate::service::Origin::Anonymous => wire.push(0),
        crate::service::Origin::Member(subject) => {
            wire.push(1);
            wire.extend_from_slice(&subject.0);
        }
        crate::service::Origin::Actor(actor) => {
            wire.push(2);
            wire.extend_from_slice(&actor.0);
        }
        crate::service::Origin::System => wire.push(3),
    }
}

#[cfg(all(feature = "storage", feature = "network"))]
fn decode_service_origin(wire: &[u8], cursor: &mut usize) -> Option<crate::service::Origin> {
    let tag = *wire.get(*cursor)?;
    *cursor += 1;
    match tag {
        0 => Some(crate::service::Origin::Anonymous),
        1 | 2 => {
            let end = cursor.checked_add(32)?;
            let bytes: [u8; 32] = wire.get(*cursor..end)?.try_into().ok()?;
            *cursor = end;
            (tag == 1)
                .then_some(crate::service::Origin::Member(crate::service::SubjectId(
                    bytes,
                )))
                .or({
                    Some(crate::service::Origin::Actor(crate::service::ActorId(
                        bytes,
                    )))
                })
        }
        3 => Some(crate::service::Origin::System),
        _ => None,
    }
}

#[cfg(all(feature = "storage", feature = "network"))]
fn encode_service_raft_redirect(
    leader_prefix: u16,
    origin: crate::service::Origin,
    root_upgrade_request: bool,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(37);
    wire.push(SERVICE_RAFT_REDIRECT_STATUS);
    wire.extend_from_slice(&leader_prefix.to_le_bytes());
    encode_service_origin(&mut wire, origin);
    wire.push(u8::from(root_upgrade_request));
    wire
}

/// Turn only a typed Raft leadership handoff into a transport redirect.
/// Storage/configuration failures remain terminal, and a stale self-hint is
/// rejected so an old leader cannot bounce the exact invocation back to itself.
#[cfg(all(feature = "storage", feature = "network"))]
fn encode_service_raft_leadership_redirect(
    failure: &crate::service::ReplicatedServiceError<crate::commit::CommitError>,
    leader_hint: Option<u16>,
    local_prefix: u16,
    origin: crate::service::Origin,
    root_upgrade_request: bool,
) -> Option<Vec<u8>> {
    matches!(
        failure,
        crate::service::ReplicatedServiceError::Log(crate::commit::CommitError::LeadershipLost)
    )
    .then_some(())?;
    let leader_prefix = leader_hint.filter(|leader| *leader != local_prefix)?;
    Some(encode_service_raft_redirect(
        leader_prefix,
        origin,
        root_upgrade_request,
    ))
}

#[cfg(all(feature = "storage", feature = "network"))]
fn decode_service_raft_redirect(wire: &[u8]) -> Option<RaftRedirect> {
    if wire.first().copied() != Some(SERVICE_RAFT_REDIRECT_STATUS) || wire.len() < 4 {
        return None;
    }
    let leader_prefix = u16::from_le_bytes([wire[1], wire[2]]);
    let mut cursor = 3;
    let origin = decode_service_origin(wire, &mut cursor)?;
    let root_upgrade_request = match wire.get(cursor) {
        Some(0) => false,
        Some(1) => true,
        _ => return None,
    };
    cursor += 1;
    (cursor == wire.len()).then_some(RaftRedirect {
        leader_prefix,
        origin,
        root_upgrade_request,
    })
}

#[cfg(all(feature = "storage", feature = "network"))]
fn encode_service_raft_delegation(
    origin: crate::service::Origin,
    preserve_envelope: bool,
    role_authority_request: bool,
    root_upgrade_request: bool,
    ingress: &[u8],
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(8 + 32 + ingress.len());
    wire.extend_from_slice(&SERVICE_RAFT_DELEGATION_MAGIC);
    wire.push(u8::from(preserve_envelope));
    wire.push(u8::from(role_authority_request));
    wire.push(u8::from(root_upgrade_request));
    encode_service_origin(&mut wire, origin);
    wire.extend_from_slice(ingress);
    wire
}

#[cfg(all(feature = "storage", feature = "network"))]
fn decode_service_raft_delegation(wire: &[u8]) -> Result<Option<RaftDelegatedIngress>, ()> {
    if !wire.starts_with(&SERVICE_RAFT_DELEGATION_MAGIC) {
        return Ok(None);
    }
    let preserve_envelope = match wire.get(4) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(()),
    };
    let role_authority_request = match wire.get(5) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(()),
    };
    let root_upgrade_request = match wire.get(6) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(()),
    };
    let mut cursor = 7;
    let origin = decode_service_origin(wire, &mut cursor).ok_or(())?;
    let ingress = wire
        .get(cursor..)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(())?;
    Ok(Some(RaftDelegatedIngress {
        origin,
        preserve_envelope,
        role_authority_request,
        root_upgrade_request,
        ingress: ingress.to_vec(),
    }))
}

#[derive(Default)]
struct RootThreadState {
    pending_callers: HashMap<crate::service::InvocationId, Vec<PendingCaller>>,
    publication_progress: HashMap<crate::service::Hash, PublicationProgress>,
    /// Bounded, acknowledged CRDT anti-entropy progress. This state is only a
    /// transport optimization: losing it restarts at chunk zero, which guest
    /// Accumulate safely classifies as an idempotent causal import.
    #[cfg(all(feature = "network", feature = "storage"))]
    crdt_sync: Option<CrdtSyncProgress>,
}

#[cfg(all(feature = "network", feature = "storage"))]
struct CrdtSyncProgress {
    /// Newest local frontier offered after a peer finishes its current
    /// immutable transfer. Replacing these fields never resets topology or a
    /// peer's acknowledged chunk cursor.
    latest_frontier: crate::service::Hash,
    latest_transfer: crate::service::Hash,
    latest_chunks: Arc<Vec<crate::service::CrdtSyncEnvelope>>,
    peers: HashMap<Vec<u8>, CrdtPeerProgress>,
    /// Full identities observed during the current successful roster scan.
    /// Peers absent when the scan closes are evicted together with any
    /// transfer generation they retained.
    roster_seen: HashSet<Vec<u8>>,
    roster_after_kind: u8,
    roster_after_key: Vec<u8>,
    next_roster_page: Instant,
    /// Last peer attempted for transport. The next drive starts strictly after
    /// this full identity, so an early group of unreachable or unauthorized
    /// peers cannot consume every bounded fan-out window forever.
    fanout_after: Option<Vec<u8>>,
}

#[cfg(all(feature = "network", feature = "storage"))]
impl CrdtSyncProgress {
    fn replace_latest(
        &mut self,
        frontier: crate::service::Hash,
        transfer: crate::service::Hash,
        chunks: Vec<crate::service::CrdtSyncEnvelope>,
    ) {
        self.latest_frontier = frontier;
        self.latest_transfer = transfer;
        self.latest_chunks = Arc::new(chunks);
    }

    fn finish_roster_scan(&mut self) {
        self.peers.retain(|peer, _| self.roster_seen.contains(peer));
        self.roster_seen.clear();
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Default)]
struct CrdtPeerProgress {
    /// The peer finishes this immutable transfer even if the local frontier
    /// advances. Old chunk vectors are shared only by peers still using them
    /// and are released automatically after their final acknowledgement.
    transfer: Option<crate::service::Hash>,
    chunks: Option<Arc<Vec<crate::service::CrdtSyncEnvelope>>>,
    next_chunk: u32,
    /// Retry throttle for the current chunk (and for failed authorization).
    last_sent: Option<Instant>,
    /// Set only while one chunk lacks an acknowledgement. Fair-scheduling
    /// time after an acknowledgement does not count toward the stall limit.
    awaiting_ack_since: Option<Instant>,
}

#[cfg(all(feature = "network", feature = "storage"))]
impl CrdtPeerProgress {
    fn needs_transfer(&self, latest_transfer: crate::service::Hash) -> bool {
        self.transfer != Some(latest_transfer)
            || self
                .chunks
                .as_ref()
                .is_some_and(|chunks| (self.next_chunk as usize) < chunks.len())
    }

    fn release_transfer(&mut self) {
        self.transfer = None;
        self.chunks = None;
        self.next_chunk = 0;
        self.last_sent = None;
        self.awaiting_ack_since = None;
    }

    fn release_stalled_transfer(&mut self, now: Instant, stall: Duration) -> bool {
        if self
            .awaiting_ack_since
            .is_some_and(|last| now.saturating_duration_since(last) >= stall)
        {
            self.release_transfer();
            true
        } else {
            false
        }
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_select_latest_peer_transfer(
    peer: &mut CrdtPeerProgress,
    latest_transfer: crate::service::Hash,
    latest_chunks: &Arc<Vec<crate::service::CrdtSyncEnvelope>>,
) {
    let complete = peer
        .chunks
        .as_ref()
        .is_none_or(|chunks| peer.next_chunk as usize >= chunks.len());
    if complete && peer.transfer != Some(latest_transfer) {
        peer.transfer = Some(latest_transfer);
        peer.chunks = Some(latest_chunks.clone());
        peer.next_chunk = 0;
        peer.last_sent = None;
        peer.awaiting_ack_since = None;
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
struct CrdtRosterPage {
    peers: Vec<libp2p::PeerId>,
    next: Option<(u8, Vec<u8>)>,
}

/// Type-erased proof backend shared only between one root thread and that
/// root's Accumulate host. The mutex serializes expensive production with
/// verification and keeps the backend out of node-global shared state.
trait NodeAttestationProofProducerDyn: Send {
    fn prove(
        &mut self,
        request: &crate::AttestationProofRequest<'_>,
    ) -> Result<crate::ProducedAttestationProof, ()>;

    fn verify(&mut self, request: &crate::service::ProofVerificationRequest, proof: &[u8]) -> bool;
}

impl<P> NodeAttestationProofProducerDyn for P
where
    P: crate::AttestationProofBackend + Send,
{
    fn prove(
        &mut self,
        request: &crate::AttestationProofRequest<'_>,
    ) -> Result<crate::ProducedAttestationProof, ()> {
        crate::AttestationProofProducer::prove(self, request).map_err(|_| ())
    }

    fn verify(&mut self, request: &crate::service::ProofVerificationRequest, proof: &[u8]) -> bool {
        if <crate::service::AttestationProofManifest as crate::service::ServiceWire>::decode(proof)
            .is_err()
        {
            return false;
        }
        crate::AttestationProofVerifier::verify(self, request, proof).unwrap_or(false)
    }
}

#[derive(Clone)]
struct NodeAttestationProofProducer(Arc<Mutex<Box<dyn NodeAttestationProofProducerDyn>>>);

type NodeAttestationProofVerifier =
    Arc<dyn Fn(&crate::service::ProofVerificationRequest, &[u8]) -> bool + Send + Sync + 'static>;

fn service_deny_all_proof_verifier() -> NodeAttestationProofVerifier {
    Arc::new(|_, _| false)
}

fn service_node_attestation_proof_verifier<V>(verifier: V) -> NodeAttestationProofVerifier
where
    V: crate::AttestationProofVerifier + Send + 'static,
{
    let verifier = Arc::new(Mutex::new(verifier));
    Arc::new(move |request, proof| {
        if <crate::service::AttestationProofManifest as crate::service::ServiceWire>::decode(proof)
            .is_err()
        {
            return false;
        }
        verifier
            .lock()
            .map(|mut verifier| {
                crate::AttestationProofVerifier::verify(&mut *verifier, request, proof)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    })
}

impl NodeAttestationProofProducer {
    fn new<P>(producer: P) -> Self
    where
        P: crate::AttestationProofBackend + Send + 'static,
    {
        Self(Arc::new(Mutex::new(Box::new(producer))))
    }

    fn verifier(&self) -> NodeAttestationProofVerifier {
        let backend = self.0.clone();
        Arc::new(move |request, proof| {
            backend
                .lock()
                .map(|mut backend| backend.verify(request, proof))
                .unwrap_or(false)
        })
    }
}

impl crate::AttestationProofProducer for NodeAttestationProofProducer {
    type Error = ();

    fn prove(
        &mut self,
        request: &crate::AttestationProofRequest<'_>,
    ) -> Result<crate::ProducedAttestationProof, Self::Error> {
        self.0.lock().map_err(|_| ())?.prove(request)
    }
}

fn install_service_root_proof_verifier<B>(
    service: &mut crate::service::LocalRootTreeService<B>,
    verifier: Option<NodeAttestationProofVerifier>,
) -> Result<(), NodeRegistrationError>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let verifier = verifier.unwrap_or_else(service_deny_all_proof_verifier);
    service.store_mut().install_proof_verifier_arc(verifier);
    service
        .store_mut()
        .ensure_proof_verifier_provenance()
        .map_err(|_| NodeRegistrationError::CorruptServiceStore)?;
    service
        .refresh_proof_provenance_snapshot()
        .map_err(|_| NodeRegistrationError::CorruptServiceStore)
}

struct PendingCaller {
    reply: ReplyChannel,
    /// Platform protocols may expose a stronger host result than the actor's
    /// committed reply bytes. The role authority uses this to return the
    /// receipt-bound assertion while its receipt continues to commit the
    /// actor-produced claim bytes exactly.
    override_result: Option<Result<Vec<u8>, u8>>,
    attested: bool,
}

#[derive(Default)]
struct PublicationProgress {
    accepted_calls: std::collections::BTreeSet<crate::service::CallId>,
    reply_accepted: bool,
}

fn service_actor_route(
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    actor: crate::service::ActorId,
) -> Option<ActorRoute> {
    actor_routes.read().ok()?.get(&actor).cloned()
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_transport_destination_route(
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    payload: &[u8],
) -> Option<ActorRoute> {
    use crate::service::ServiceWire;

    let transport = crate::service::RootTreeTransport::decode(payload).ok()?;
    let routes = actor_routes.read().ok()?;
    match transport {
        crate::service::RootTreeTransport::OutboxDelivery { message, .. } => routes
            .get(&message.to)
            .filter(|route| route.service == message.to_service)
            .cloned(),
        crate::service::RootTreeTransport::Reply {
            caller,
            caller_service,
            ..
        } => routes
            .get(&caller)
            .filter(|route| route.service == caller_service)
            .cloned(),
        crate::service::RootTreeTransport::PublicationAccepted { service, .. } => routes
            .values()
            .find(|route| route.service == service)
            .cloned(),
        crate::service::RootTreeTransport::CrdtSyncChunk { envelope, .. } => routes
            .values()
            .find(|route| {
                route.service == envelope.service
                    && route.consistency == crate::service::ConsistencyMode::Crdt
                    && route.authenticated_peer.is_none()
            })
            .cloned(),
        crate::service::RootTreeTransport::CrdtSyncAccepted { service, .. } => routes
            .values()
            .find(|route| {
                route.service == service
                    && route.consistency == crate::service::ConsistencyMode::Crdt
                    && route.authenticated_peer.is_none()
            })
            .cloned(),
    }
}

#[cfg(feature = "network")]
fn service_transport_source_route(
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    payload: &[u8],
) -> Option<ActorRoute> {
    use crate::service::ServiceWire;

    let transport = crate::service::RootTreeTransport::decode(payload).ok()?;
    let routes = actor_routes.read().ok()?;
    let (actor, service) = match transport {
        crate::service::RootTreeTransport::OutboxDelivery { message, .. } => {
            (message.from, message.from_service)
        }
        crate::service::RootTreeTransport::Reply { publication, .. } => {
            let reply = publication.published.reply?;
            (reply.producer, publication.receipt.service)
        }
        crate::service::RootTreeTransport::PublicationAccepted {
            acceptor,
            acceptor_service,
            ..
        } => (acceptor, acceptor_service),
        crate::service::RootTreeTransport::CrdtSyncChunk { .. }
        | crate::service::RootTreeTransport::CrdtSyncAccepted { .. } => return None,
    };
    routes
        .get(&actor)
        .filter(|route| route.service == service)
        .cloned()
}

/// Authenticate one CRDT replica by its complete Noise identity and the
/// canonical enrolled-node row. A compact route prefix is used only to locate
/// the row; collisions never satisfy the final full-PeerId comparison.
#[cfg(all(feature = "network", feature = "storage"))]
fn authenticated_service_crdt_replica_peer(
    invoke_routes: &InvokeRoutes,
    peer_bytes: &[u8],
    timeout: Duration,
) -> Option<libp2p::PeerId> {
    let peer = libp2p::PeerId::from_bytes(peer_bytes).ok()?;
    let prefix = crate::network::derive_node_prefix(&peer);
    let member = lookup_node_member_from_routes_with_timeout(invoke_routes, prefix, timeout)?;
    (member.kind == crate::registry::MEMBER_KIND_NODE
        && matches!(
            member.role,
            crate::registry::NODE_ROLE_VOTER | crate::registry::NODE_ROLE_OBSERVER
        )
        && member.prefix == prefix
        && member.key == peer_bytes)
        .then_some(peer)
}

/// Read one canonical node-roster page. The opaque cursor is retained by the
/// root thread, so registries larger than one host-side scan budget continue
/// from their last page instead of restarting at the first 1,024 rows.
#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_replica_roster_page(
    invoke_routes: &InvokeRoutes,
    after_kind: u8,
    after_key: Vec<u8>,
    timeout: Duration,
) -> Option<CrdtRosterPage> {
    use crate::actors::codec::{Decode, Encode};
    use crate::registry::{MEMBER_KIND_NODE, MemberPage};
    use crate::value::{Msg, TAG_DYNAMIC, Value};

    let msg = Msg::new("members")
        .with("after_kind", after_kind)
        .with("after_key", after_key)
        .with("budget", 64u32);
    let mut payload = Vec::with_capacity(1 + 64);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    let reply = registry_probe_reply_with_timeout(invoke_routes, payload, timeout)?;
    let Value::Bytes(bytes) = <Value as Decode>::try_decode(&reply)? else {
        return None;
    };
    let page = <MemberPage as Decode>::try_decode(&bytes)?;
    let mut peers = Vec::new();
    for member in page.members {
        if member.kind != MEMBER_KIND_NODE
            || !matches!(
                member.role,
                crate::registry::NODE_ROLE_VOTER | crate::registry::NODE_ROLE_OBSERVER
            )
        {
            continue;
        }
        let Ok(peer) = libp2p::PeerId::from_bytes(&member.key) else {
            continue;
        };
        if crate::network::derive_node_prefix(&peer) == member.prefix {
            peers.push(peer);
        }
    }
    peers.sort();
    peers.dedup();
    let next = (page.more && page.next_kind == MEMBER_KIND_NODE)
        .then_some((page.next_kind, page.next_key));
    Some(CrdtRosterPage { peers, next })
}

/// Resolve the same per-agent sync floor used by the pull service.
/// Unknown catalog state is distinct from `Member`: callers must deny it so a
/// timeout, malformed response, or lagging registry cannot open a private
/// replica.
#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_sync_floor(
    invoke_routes: &InvokeRoutes,
    name: &str,
    timeout: Duration,
) -> Option<crate::registry::SyncFloor> {
    use crate::actors::codec::Encode;
    use crate::registry::SyncFloor;
    use crate::value::{Msg, TAG_DYNAMIC};

    match name {
        "" => return Some(SyncFloor::Public),
        REGISTRY_AGENT_NAME => return Some(SyncFloor::Member),
        HYPERSPACE_REGISTRY_AGENT_NAME => return Some(SyncFloor::Public),
        _ => {}
    }
    let msg = Msg::new("service_actor").with("instance_name", name);
    let mut payload = Vec::with_capacity(1 + 64);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    registry_probe_reply_with_timeout(invoke_routes, payload, timeout)
        .and_then(|reply| decode_registry_bytes_reply::<crate::registry::AgentLookup>(&reply))
        .filter(|lookup| lookup.protocol.is_current())
        .and_then(|lookup| lookup.row)
        .filter(|row| row.instance_name == name)
        .map(|row| row.sync_role)
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_registry_role(
    invoke_routes: &InvokeRoutes,
    peer: &libp2p::PeerId,
    timeout: Duration,
) -> u8 {
    use crate::actors::codec::Encode;
    use crate::value::{Msg, TAG_DYNAMIC};

    let msg = Msg::new("peer_role").with("peer_id", peer.to_bytes());
    let mut payload = Vec::with_capacity(1 + 96);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    registry_probe_reply_with_timeout(invoke_routes, payload, timeout)
        .and_then(|reply| decode_u8_reply(&reply))
        .unwrap_or(AUTH_ROLE_NONE)
}

/// Apply the established sync-floor policy after exact enrolled-node
/// authentication. Enrollment satisfies `Member`, but deliberately does not
/// satisfy `Private`; private state requires a space read grant.
#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_sync_peer_allowed(
    invoke_routes: &InvokeRoutes,
    peer: &libp2p::PeerId,
    name: &str,
    timeout: Duration,
) -> bool {
    use crate::registry::SyncFloor;

    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    match service_crdt_sync_floor(
        invoke_routes,
        name,
        deadline.saturating_duration_since(Instant::now()),
    ) {
        Some(SyncFloor::Public | SyncFloor::Member) => true,
        Some(SyncFloor::Private) => {
            service_crdt_registry_role(
                invoke_routes,
                peer,
                deadline.saturating_duration_since(Instant::now()),
            ) >= AUTH_ROLE_READONLY
        }
        None => false,
    }
}

/// Return full peer identities in a stable cyclic order beginning strictly
/// after the previous authentication attempt. The cursor is a key rather than
/// a numeric index so roster growth does not reset progress to the first peers.
#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_fanout_order(mut peers: Vec<Vec<u8>>, after: Option<&[u8]>) -> Vec<Vec<u8>> {
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        return peers;
    }
    if let Some(after) = after {
        let start = peers.partition_point(|peer| peer.as_slice() <= after);
        let len = peers.len();
        peers.rotate_left(start % len);
    }
    peers
}

/// Leave a full MiB for the outer Tell frame and future transport fields.
/// The network hard cap is 8 MiB; every encoded VRT2 chunk is checked against
/// this smaller bound before it can enter the node outbox.
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_CRDT_SYNC_CHUNK_MAX_BYTES: usize = 7 * 1024 * 1024;

/// Thirty seconds with one unacknowledged chunk retire only that peer's
/// immutable snapshot. Time spent waiting for the next fair fan-out turn is
/// excluded. Recovery restarts from the newest transfer and guest dedup makes
/// already imported chunks harmless.
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_CRDT_SYNC_TRANSFER_STALL: Duration = Duration::from_secs(30);

/// Bound synchronous authentication work as well as successful sends. Each
/// attempt may perform both registry identity and sync-floor resolution.
#[cfg(all(feature = "network", feature = "storage"))]
const SERVICE_CRDT_SYNC_ATTEMPT_BUDGET: usize = 4;

#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_sync_delta(
    service: &crate::service::ServiceIdentity,
    heads: &BTreeSet<crate::service::Hash>,
    nodes: &[crate::service::CrdtSyncNode],
    blobs: &BTreeMap<crate::service::Hash, crate::service::ImportedBlob>,
) -> crate::service::CrdtSyncEnvelope {
    let mut nodes = nodes.to_vec();
    nodes.sort_by_key(|node| node.change.cid());
    crate::service::CrdtSyncEnvelope {
        service: service.clone(),
        advertised_heads: heads.iter().copied().collect(),
        nodes,
        provided_blobs: blobs.values().cloned().collect(),
    }
}

/// Split a complete export into causal, guest-committable deltas. Nodes are
/// considered by height, while each individual envelope remains CID-sorted
/// as required by VCS2. The intermediate advertised frontier means a peer can
/// commit and acknowledge every chunk independently; no process-memory
/// reassembly is trusted for correctness or restart recovery.
#[cfg(all(feature = "network", feature = "storage"))]
fn service_crdt_sync_chunks(
    envelope: crate::service::CrdtSyncEnvelope,
    max_payload_bytes: usize,
) -> Result<(crate::service::Hash, Vec<crate::service::CrdtSyncEnvelope>), &'static str> {
    use crate::service::ServiceWire;

    let transfer = envelope.commitment();
    if transfer == crate::service::Hash::ZERO || envelope.nodes.is_empty() {
        return Err("empty CRDT synchronization export");
    }
    let mut ordered = envelope.nodes.clone();
    ordered.sort_by_key(|node| (node.change.causal_height, node.change.cid()));
    let available_blobs = envelope
        .provided_blobs
        .iter()
        .cloned()
        .map(|blob| (blob.reference.hash, blob))
        .collect::<BTreeMap<_, _>>();
    let mut frontier = BTreeSet::new();
    let mut current_nodes = Vec::new();
    let mut current_blobs = BTreeMap::new();
    let mut current_node_bytes = 0usize;
    let mut current_blob_bytes = 0usize;
    let mut chunks = Vec::new();

    // Derive the fixed wire cost from the codecs themselves. The empty shape
    // is used only for sizing (it is never decoded or transmitted); variable
    // heads, nodes and blobs are accounted below.
    let fixed_wire_bytes = crate::service::RootTreeTransport::CrdtSyncChunk {
        transfer,
        chunk_index: 0,
        chunk_count: u32::MAX,
        envelope: crate::service::CrdtSyncEnvelope {
            service: envelope.service.clone(),
            advertised_heads: Vec::new(),
            nodes: Vec::new(),
            provided_blobs: Vec::new(),
        },
    }
    .encode()
    .len();

    for node in ordered {
        let mut next_frontier = frontier.clone();
        for dependency in &node.change.causal_dependencies {
            next_frontier.remove(dependency);
        }
        next_frontier.insert(node.change.cid());
        let node_bytes = 8usize
            .saturating_add(node.change.encode().len())
            .saturating_add(node.receipt.encode().len());
        let mut added_blobs = BTreeMap::new();
        for reference in crate::service::crdt_change_blob_references(&node.change) {
            let Some(blob) = available_blobs.get(&reference.hash) else {
                return Err("complete CRDT export omitted a referenced blob");
            };
            if blob.reference != *reference {
                return Err("CRDT blob hash aliases a different reference");
            }
            if !current_blobs.contains_key(&reference.hash) {
                added_blobs.insert(reference.hash, blob.clone());
            }
        }
        let added_blob_bytes = added_blobs.values().fold(0usize, |total, blob| {
            total.saturating_add(44usize.saturating_add(blob.bytes.len()))
        });
        let candidate_bytes = fixed_wire_bytes
            .saturating_add(next_frontier.len().saturating_mul(32))
            .saturating_add(current_node_bytes)
            .saturating_add(node_bytes)
            .saturating_add(current_blob_bytes)
            .saturating_add(added_blob_bytes);
        if candidate_bytes <= max_payload_bytes {
            frontier = next_frontier;
            current_nodes.push(node);
            current_blobs.extend(added_blobs);
            current_node_bytes = current_node_bytes.saturating_add(node_bytes);
            current_blob_bytes = current_blob_bytes.saturating_add(added_blob_bytes);
            continue;
        }
        if current_nodes.is_empty() {
            return Err("one CRDT causal node exceeds the transport frame budget");
        }
        chunks.push(service_crdt_sync_delta(
            &envelope.service,
            &frontier,
            &current_nodes,
            &current_blobs,
        ));

        frontier = next_frontier;
        current_nodes = vec![node];
        current_blobs = added_blobs;
        current_node_bytes = node_bytes;
        current_blob_bytes = added_blob_bytes;
        let single_bytes = fixed_wire_bytes
            .saturating_add(frontier.len().saturating_mul(32))
            .saturating_add(current_node_bytes)
            .saturating_add(current_blob_bytes);
        if single_bytes > max_payload_bytes {
            return Err("one CRDT causal node exceeds the transport frame budget");
        }
    }
    if !current_nodes.is_empty() {
        chunks.push(service_crdt_sync_delta(
            &envelope.service,
            &frontier,
            &current_nodes,
            &current_blobs,
        ));
    }
    let expected = envelope
        .advertised_heads
        .into_iter()
        .collect::<BTreeSet<_>>();
    if frontier != expected || chunks.len() > u32::MAX as usize {
        return Err("CRDT export did not reduce to its advertised frontier");
    }
    let chunk_count = chunks.len() as u32;
    for (index, chunk) in chunks.iter().enumerate() {
        let wire = crate::service::RootTreeTransport::CrdtSyncChunk {
            transfer,
            chunk_index: index as u32,
            chunk_count,
            envelope: chunk.clone(),
        }
        .encode();
        if wire.len() > max_payload_bytes
            || crate::service::RootTreeTransport::decode(&wire).is_err()
        {
            return Err("constructed a non-canonical or oversized CRDT transport chunk");
        }
    }
    Ok((transfer, chunks))
}

/// Resolve one claimed actor through its exact route and authenticated peer.
/// Comparing only the compact route is unsafe because different PeerIds can
/// collide on its 16-bit node prefix and reuse the same local-id suffix.
#[cfg(test)]
fn authenticated_service_actor_route(
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    actor: crate::service::ActorId,
    route: ServiceId,
    authenticated_peer: Option<&[u8]>,
) -> Option<ActorRoute> {
    let binding = service_actor_route(actor_routes, actor)?;
    (binding.route == route.0 && binding.authenticated_peer.as_deref() == authenticated_peer)
        .then_some(binding)
}

/// Authenticate a Raft transport hop against the current leader's complete
/// Noise identity. Actor-route bindings retain one bootstrap replica, but the
/// authority to emit or acknowledge transport follows the replication group,
/// not that process. Compact prefixes are used only as Raft member slots and
/// are always resolved through the canonical NODE roster before acceptance.
#[cfg(all(feature = "network", feature = "storage"))]
fn raft_route_peer_is_current_leader(
    binding: &ActorRoute,
    route: ServiceId,
    peer_bytes: &[u8],
    network: &crate::network::Network,
    invoke_routes: &InvokeRoutes,
) -> bool {
    let Some(replication_id) = binding.replication_id else {
        return false;
    };
    if ServiceId(binding.route).local_id() != route.local_id() {
        return false;
    }
    let Ok(peer) = libp2p::PeerId::from_bytes(peer_bytes) else {
        return false;
    };
    let prefix = crate::network::derive_node_prefix(&peer);
    if prefix != route.node_prefix() {
        return false;
    }
    let Some(member) = lookup_node_member_from_routes(invoke_routes, prefix) else {
        return false;
    };
    if !node_member_authenticates_active_slot(&member, prefix, &peer) {
        return false;
    }
    network
        .send_raft_status_req(peer, replication_id)
        .recv_timeout(Duration::from_millis(SERVICE_RAFT_VOTER_AUTH_TIMEOUT_MS))
        .ok()
        .is_some_and(|status| {
            status.present
                && status.role == crate::network::RaftRole::Leader
                && status.leader_hint == Some(prefix)
                && status.is_active_voter(prefix)
        })
}

#[cfg(all(feature = "network", feature = "storage", test))]
fn resolve_service_raft_leader_route(
    binding: &ActorRoute,
    network: &crate::network::Network,
    invoke_routes: &InvokeRoutes,
) -> Option<(libp2p::PeerId, ServiceId)> {
    resolve_service_raft_leader_route_before(
        binding,
        network,
        invoke_routes,
        Instant::now() + SERVICE_RAFT_TRANSPORT_RESOLUTION_TIMEOUT,
        0,
    )
    .0
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_raft_transport_resolution_deadlines(now: Instant) -> (Instant, Instant) {
    let resolution_deadline = now + SERVICE_RAFT_TRANSPORT_RESOLUTION_TIMEOUT;
    let ownership_until = resolution_deadline + SERVICE_RAFT_TRANSPORT_RESOLUTION_OWNERSHIP_GRACE;
    (resolution_deadline, ownership_until)
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_raft_transport_auth_windows(now: Instant, deadline: Instant) -> (Duration, Instant) {
    let auth_window = deadline
        .saturating_duration_since(now)
        .checked_div(2)
        .unwrap_or_default();
    (auth_window, now + auth_window)
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_raft_transport_status_deadline(auth_deadline: Instant, deadline: Instant) -> Instant {
    auth_deadline
        + deadline
            .saturating_duration_since(auth_deadline)
            .checked_div(2)
            .unwrap_or_default()
}

#[cfg(all(feature = "network", feature = "storage"))]
fn resolve_service_raft_leader_route_before(
    binding: &ActorRoute,
    network: &crate::network::Network,
    invoke_routes: &InvokeRoutes,
    deadline: Instant,
    candidate_cursor: usize,
) -> (Option<(libp2p::PeerId, ServiceId)>, usize) {
    let Some(replication_id) = binding.replication_id else {
        return (None, candidate_cursor);
    };
    let local_id = ServiceId(binding.route).local_id();

    // The local view is worker-published rather than inbox-driven: a wedged
    // follower must not create one detached status thread per durable retry.
    let local_status = network.local_raft_status_cached(&replication_id);

    // Preserve the exact install-time bootstrap separately so ambient peers
    // can neither replace it nor divide away its authentication budget.
    let exact_bootstrap = binding
        .authenticated_peer
        .as_deref()
        .and_then(|bytes| libp2p::PeerId::from_bytes(bytes).ok())
        .map(|peer| (crate::network::derive_node_prefix(&peer), peer));

    // Prefer the fresh worker-published voter roster. Connected peers are a
    // bounded fallback for a remote root with no local observation; each is
    // still authenticated against the canonical NODE row below.
    let mut candidates = Vec::new();
    if let Some(status) = local_status.as_ref() {
        if let Some(prefix) = status.leader_hint {
            push_service_raft_prefix_candidate(&mut candidates, prefix);
        }
        for prefix in status.active_voters() {
            if candidates.len() >= SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES {
                break;
            }
            push_service_raft_prefix_candidate(&mut candidates, prefix);
        }
    }
    let connected = network
        .connected_peers()
        .into_iter()
        .filter(|peer| {
            exact_bootstrap
                .as_ref()
                .is_none_or(|(_, exact)| exact != peer)
        })
        .collect::<Vec<_>>();
    let (connected_window, next_candidate_cursor) = service_raft_connected_candidate_window(
        connected,
        candidate_cursor,
        SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES.saturating_sub(candidates.len()),
    );
    for peer in connected_window {
        if candidates.len() >= SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES {
            break;
        }
        let prefix = crate::network::derive_node_prefix(&peer);
        push_service_raft_peer_candidate(&mut candidates, prefix, peer);
    }

    // Spend at most half the shared deadline on roster authentication. The
    // exact bootstrap owns that whole budget independently; if it answers
    // earlier, ambient candidates may divide only the time it leaves. The
    // latter population is bounded above and stale disconnected peers are
    // evicted by the network layer.
    let auth_started = Instant::now();
    let (bootstrap_budget, auth_deadline) =
        service_raft_transport_auth_windows(auth_started, deadline);
    let mut authenticated = HashMap::new();
    if let Some((prefix, peer)) = exact_bootstrap
        && let Some((peer, member)) = authenticate_service_raft_peer_candidate(
            invoke_routes,
            prefix,
            Some(peer),
            bootstrap_budget,
        )
    {
        authenticated.insert(prefix, (peer, member));
    }
    let candidate_count = candidates.len();
    for (index, (prefix, expected_peer)) in candidates.into_iter().enumerate() {
        if authenticated.contains_key(&prefix) {
            continue;
        }
        let candidates_left = candidate_count.saturating_sub(index).max(1) as u32;
        let remaining = auth_deadline.saturating_duration_since(Instant::now());
        let budget = remaining.checked_div(candidates_left).unwrap_or_default();
        if budget.is_zero() {
            continue;
        }
        let Some((peer, member)) =
            authenticate_service_raft_peer_candidate(invoke_routes, prefix, expected_peer, budget)
        else {
            continue;
        };
        authenticated.insert(prefix, (peer, member));
    }

    // Fan out before waiting for any response. A responsive-but-stalled old
    // bootstrap can consume its own request lifetime, but it cannot prevent a
    // newly elected connected voter from answering within the shared bound.
    // Stop before the overall deadline so a trusted follower's previously
    // unseen leader hint can still be bound through the canonical roster.
    let mut probes = authenticated
        .iter()
        .map(|(&prefix, (peer, _))| (prefix, network.send_raft_status_req(*peer, replication_id)))
        .collect::<Vec<_>>();
    let mut observations = local_status
        .into_iter()
        .map(|status| {
            (
                crate::network::derive_node_prefix(&network.peer_id()),
                status,
            )
        })
        .collect::<Vec<_>>();
    let status_deadline = service_raft_transport_status_deadline(auth_deadline, deadline);
    observations.extend(collect_service_raft_status_probes(
        &mut probes,
        status_deadline,
    ));

    // A cache is only one observation, never an authority to short-circuit
    // live voters. Prefer the highest term seen across every authenticated
    // reply. The selected term's bounded leader hints are authenticated after
    // collection, so a trusted bootstrap follower can introduce a leader that
    // was absent from both the local cache and connected-peer fallback.
    (
        resolve_service_raft_leader_observations(
            observations,
            &authenticated,
            invoke_routes,
            local_id,
            deadline,
        ),
        next_candidate_cursor,
    )
}

#[cfg(all(feature = "network", feature = "storage"))]
fn service_raft_connected_candidate_window(
    mut peers: Vec<libp2p::PeerId>,
    cursor: usize,
    limit: usize,
) -> (Vec<libp2p::PeerId>, usize) {
    if peers.is_empty() || limit == 0 {
        return (Vec::new(), cursor);
    }
    // `connected_peers` preserves the prefix map's iteration order while its
    // population is unchanged. Advancing by the number actually selected
    // therefore covers a fixed set even when trusted local candidates leave
    // fewer than sixteen fallback slots.
    let start = cursor % peers.len();
    peers.rotate_left(start);
    let selected = limit.min(peers.len());
    peers.truncate(selected);
    (peers, start.wrapping_add(selected))
}

#[cfg(all(feature = "network", feature = "storage"))]
fn authenticate_service_raft_peer_candidate(
    invoke_routes: &InvokeRoutes,
    prefix: u16,
    expected_peer: Option<libp2p::PeerId>,
    budget: Duration,
) -> Option<(libp2p::PeerId, crate::registry::MemberRow)> {
    if budget.is_zero() {
        return None;
    }
    let member = lookup_node_member_from_routes_with_timeout(invoke_routes, prefix, budget)?;
    let peer = expected_peer.or_else(|| libp2p::PeerId::from_bytes(&member.key).ok())?;
    node_member_authenticates_active_slot(&member, prefix, &peer).then_some((peer, member))
}

#[cfg(all(feature = "network", feature = "storage"))]
fn push_service_raft_prefix_candidate(
    candidates: &mut Vec<(u16, Option<libp2p::PeerId>)>,
    prefix: u16,
) {
    if !candidates
        .iter()
        .any(|(candidate_prefix, candidate)| *candidate_prefix == prefix && candidate.is_none())
    {
        candidates.push((prefix, None));
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
fn push_service_raft_peer_candidate(
    candidates: &mut Vec<(u16, Option<libp2p::PeerId>)>,
    prefix: u16,
    peer: libp2p::PeerId,
) {
    if !candidates
        .iter()
        .any(|(_, candidate)| candidate.as_ref() == Some(&peer))
    {
        candidates.push((prefix, Some(peer)));
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
fn ranked_service_raft_leader_observations(
    observations: Vec<(u16, crate::network::RaftStatusReply)>,
) -> Vec<(u16, crate::network::RaftStatusReply)> {
    let mut observations = observations
        .into_iter()
        .filter(|(reporter, status)| status.present && status.is_active_voter(*reporter))
        .collect::<Vec<_>>();
    observations.sort_unstable_by_key(|(reporter, status)| {
        let self_reported_leader = status.role == crate::network::RaftRole::Leader
            && status.leader_hint == Some(*reporter);
        std::cmp::Reverse((
            status.current_term,
            self_reported_leader,
            status.commit_index,
            status.last_log_index,
            *reporter,
        ))
    });
    let Some(highest_term) = observations.first().map(|(_, status)| status.current_term) else {
        return observations;
    };
    observations.retain(|(_, status)| status.current_term == highest_term);
    observations
}

#[cfg(all(feature = "network", feature = "storage"))]
fn resolve_service_raft_leader_observations(
    observations: Vec<(u16, crate::network::RaftStatusReply)>,
    authenticated: &HashMap<u16, (libp2p::PeerId, crate::registry::MemberRow)>,
    invoke_routes: &InvokeRoutes,
    local_id: u16,
    deadline: Instant,
) -> Option<(libp2p::PeerId, ServiceId)> {
    let observations = ranked_service_raft_leader_observations(observations);
    let mut attempted = HashSet::new();
    let mut candidates = Vec::new();
    for (_, status) in observations {
        let Some(leader_prefix) = status.leader_hint else {
            continue;
        };
        if !attempted.insert(leader_prefix) {
            continue;
        }
        if attempted.len() > SERVICE_RAFT_TRANSPORT_MAX_LEADER_HINTS {
            break;
        }
        candidates.push((leader_prefix, status));
    }

    let candidate_count = candidates.len();
    for (index, (leader_prefix, status)) in candidates.into_iter().enumerate() {
        if let Some((_, member)) = authenticated.get(&leader_prefix)
            && let Some(peer) =
                authenticated_service_raft_leader_peer(&status, member, leader_prefix)
        {
            return Some((peer, ServiceId::new(leader_prefix, local_id)));
        }

        let hints_left = candidate_count.saturating_sub(index).max(1) as u32;
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .checked_div(hints_left)
            .unwrap_or_default();
        let Some((_, member)) =
            authenticate_service_raft_peer_candidate(invoke_routes, leader_prefix, None, budget)
        else {
            continue;
        };
        if let Some(peer) = authenticated_service_raft_leader_peer(&status, &member, leader_prefix)
        {
            return Some((peer, ServiceId::new(leader_prefix, local_id)));
        }
    }
    None
}

#[cfg(all(feature = "network", feature = "storage"))]
fn collect_service_raft_status_probes(
    probes: &mut Vec<(u16, mpsc::Receiver<crate::network::RaftStatusReply>)>,
    deadline: Instant,
) -> Vec<(u16, crate::network::RaftStatusReply)> {
    let mut replies = Vec::new();
    while !probes.is_empty() && Instant::now() < deadline {
        let mut index = 0;
        while index < probes.len() {
            match probes[index].1.try_recv() {
                Ok(status) => {
                    let (prefix, _) = probes.swap_remove(index);
                    replies.push((prefix, status));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    probes.swap_remove(index);
                }
                Err(mpsc::TryRecvError::Empty) => index += 1,
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() && !probes.is_empty() {
            thread::sleep(remaining.min(Duration::from_millis(2)));
        }
    }
    replies
}

#[cfg(all(feature = "network", feature = "storage"))]
fn dispatch_resolved_service_raft_transport(
    network: &crate::network::Network,
    local_tx: Option<mpsc::Sender<Envelope>>,
    peer: libp2p::PeerId,
    route: ServiceId,
    mut envelope: Envelope,
) {
    if peer == network.peer_id() {
        let Some(local_tx) = local_tx else {
            warn!(%route, "node: resolved local Raft leader has no attached root route");
            return;
        };
        envelope.to = route;
        envelope.destination_peer = None;
        let _ = local_tx.send(envelope);
    } else {
        network.send_tell(peer, envelope.from.0, route.0, envelope.payload);
    }
}

fn authenticated_service_actor_route_at_node(
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    actor: crate::service::ActorId,
    route: ServiceId,
    authenticated_peer: Option<&[u8]>,
    invoke_routes: &InvokeRoutes,
    #[cfg(feature = "network")] shared_network: &SharedNetwork,
) -> Option<ActorRoute> {
    let binding = service_actor_route(actor_routes, actor)?;
    if binding.consistency != crate::service::ConsistencyMode::Raft {
        return (binding.route == route.0
            && binding.authenticated_peer.as_deref() == authenticated_peer)
            .then_some(binding);
    }

    // Calls between roots attached to this node do not cross an identity
    // boundary. The destination's admission barrier still rejects followers.
    if binding.route == route.0
        && binding.authenticated_peer.is_none()
        && authenticated_peer.is_none()
    {
        return Some(binding);
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    {
        let peer = authenticated_peer?;
        let network = shared_network.lock().ok()?.clone()?;
        if raft_route_peer_is_current_leader(&binding, route, peer, &network, invoke_routes) {
            return Some(binding);
        }
    }
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let _ = (authenticated_peer, invoke_routes);
    #[cfg(all(feature = "network", not(feature = "storage")))]
    let _ = shared_network;
    None
}

fn prepare_service_root_slot<B>(
    service: &mut crate::service::LocalRootTreeService<B>,
    logical_timeslot: &AtomicU64,
) -> Result<u64, String>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let floor = service
        .prepare_admission_barrier()
        .map_err(|error| format!("admission barrier failed: {error}"))?;
    allocate_service_root_slot_after_barrier(service, logical_timeslot, floor)
        .map_err(|error| format!("logical-timeslot allocation failed: {error:?}"))
}

/// Allocate the final slot after a previously established service barrier.
/// Authority execution may advance the shared node clock in between; the
/// fetch-max plus allocation therefore orders delivery strictly after that
/// work without running another service catch-up between allocation and the
/// proposal.
fn allocate_service_root_slot_after_barrier<B>(
    service: &crate::service::LocalRootTreeService<B>,
    logical_timeslot: &AtomicU64,
    admission_floor: u64,
) -> Result<u64, NodeRegistrationError>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let observed = service
        .production_logical_timeslot()
        .map_err(|_| NodeRegistrationError::LogicalTimeslotUnavailable)?;
    allocate_service_observed_slot_after_barrier(logical_timeslot, admission_floor, observed)
}

fn allocate_service_observed_slot_after_barrier(
    logical_timeslot: &AtomicU64,
    admission_floor: u64,
    observed: Option<u64>,
) -> Result<u64, NodeRegistrationError> {
    if let Some(observed) = observed {
        if observed < admission_floor {
            return Err(NodeRegistrationError::LogicalTimeslotRegressed);
        }
        logical_timeslot.fetch_max(observed, Ordering::Relaxed);
        return Ok(observed);
    }
    allocate_service_conformance_slot_after_barrier(logical_timeslot, admission_floor)
}

fn service_root_slot_failure_is_terminal(failure: NodeRegistrationError) -> bool {
    matches!(failure, NodeRegistrationError::LogicalTimeslotExhausted)
}

fn allocate_service_conformance_slot_after_barrier(
    logical_timeslot: &AtomicU64,
    admission_floor: u64,
) -> Result<u64, NodeRegistrationError> {
    restore_service_logical_timeslot(logical_timeslot, admission_floor)?;
    Ok(next_service_logical_timeslot(logical_timeslot))
}

/// Ask the locally attached canonical Raft authority to finalize one exact
/// invocation-scoped role claim. A follower redirect preserves the platform
/// `System` origin through the existing voter-authenticated delegation wire;
/// the returned assertion is still checked byte-for-byte against the target
/// service's installed authority binding before it reaches guest Accumulate.
fn request_service_role_assertion(
    authority: &crate::service::RoleAuthorityBinding,
    claim: &crate::service::RoleAuthorizationClaim,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    invoke_routes: &InvokeRoutes,
    #[cfg(feature = "network")] shared_network: &SharedNetwork,
) -> Result<crate::service::AccumulatedRoleAssertion, ()> {
    use crate::{Decode, Encode, service::ServiceWire};

    let route = service_actor_route(actor_routes, authority.actor).filter(|route| {
        route.service == authority.service
            && route.consistency == crate::service::ConsistencyMode::Raft
            && route.replication_id.is_some()
            && route.is_role_authority
            && route.authenticated_peer.is_none()
    });
    let Some(route) = route else {
        return Err(());
    };
    let mut arguments = vec![crate::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &crate::value::Msg::new(crate::service::ROLE_AUTHORITY_DECISION_METHOD_)
            .with("claim", claim.encode())
            .encode(),
    );
    let ingress = crate::service::RootTreeInvocation {
        invocation: claim.authority_invocation(),
        target: authority.actor,
        method: crate::service::ROLE_AUTHORITY_DECISION_METHOD_.into(),
        arguments,
        proof_requested: false,
    };
    let ingress_wire = ingress.encode();
    let tx = invoke_routes
        .lock()
        .map_err(|_| ())?
        .get(&route.route)
        .cloned()
        .ok_or(())?;
    let deadline = Instant::now().checked_add(route.invoke_timeout).ok_or(())?;
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(InvokeRequest {
        caller: crate::actors::Caller::System,
        space_role: None,
        actor_local_role: None,
        #[cfg(all(feature = "network", feature = "storage"))]
        delegated_origin: None,
        role_authority_request: true,
        root_upgrade_request: false,
        invocation_id: None,
        native_call: None,
        msg: ingress_wire.clone(),
        reply: ReplyChannel::Sync(reply_tx),
        chain: Vec::new(),
    })
    .map_err(|_| ())?;
    let envelope = reply_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| ())?;

    #[cfg(all(feature = "network", feature = "storage"))]
    let envelope = if let Some(redirect) = decode_service_raft_redirect(&envelope) {
        let network = shared_network.lock().map_err(|_| ())?.clone().ok_or(())?;
        let replication_id = route.replication_id.ok_or(())?;
        let status = network.local_raft_status(&replication_id).ok_or(())?;
        send_service_raft_invoke_exact(
            &network,
            invoke_routes,
            &route,
            status,
            redirect.leader_prefix,
            crate::service::Origin::System,
            true,
            true,
            false,
            &ingress_wire,
            deadline,
        )
        .ok_or(())?
    } else {
        envelope
    };

    let reply = decode_host_invoke_envelope(&envelope).map_err(|_| ())?;
    let crate::value::Value::Bytes(bytes) =
        <crate::value::Value as Decode>::try_decode(&reply).ok_or(())?
    else {
        return Err(());
    };
    let assertion = crate::service::AccumulatedRoleAssertion::decode(&bytes).map_err(|_| ())?;
    if assertion.claim != *claim
        || assertion.receipt.consistency != crate::service::ConsistencyMode::Raft
        || !assertion.matches_authority(authority)
    {
        return Err(());
    }
    Ok(assertion)
}

fn role_authority_reply_override<B>(
    service: &crate::service::LocalRootTreeService<B>,
    role_authority_request: bool,
    ingress: &crate::service::RootTreeInvocation,
    committed: &crate::service::CommittedRootTreeSlice,
) -> Option<Result<Vec<u8>, u8>>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    use crate::{Decode, Encode, service::ServiceWire};

    if !role_authority_request || ingress.method != crate::service::ROLE_AUTHORITY_DECISION_METHOD_
    {
        return None;
    }
    let assertion = (|| {
        let message = <crate::value::Msg as Decode>::try_decode(
            ingress
                .arguments
                .strip_prefix(&[crate::value::TAG_DYNAMIC])?,
        )?;
        if message.name != crate::service::ROLE_AUTHORITY_DECISION_METHOD_ {
            return None;
        }
        let claim =
            crate::service::RoleAuthorizationClaim::decode(&message.args.get_bytes("claim")?)
                .ok()?;
        if claim.authority_invocation() != ingress.invocation {
            return None;
        }
        let authority = crate::service::RoleAuthorityBinding {
            service: service.identity().clone(),
            actor: ingress.target,
        };
        let assertion = if committed.duplicate {
            service.recover_role_assertion(claim, &authority).ok()?
        } else {
            committed.role_assertion(claim, &authority).ok()?
        };
        Some(crate::value::Value::Bytes(assertion.encode()).encode())
    })();
    Some(assertion.ok_or(crate::STATUS_FORBIDDEN))
}

fn service_root_service_thread<B>(
    id: ServiceId,
    root_name: String,
    mut service: crate::service::LocalRootTreeService<B>,
    inbox_rx: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    actor_routes: Arc<RwLock<HashMap<crate::service::ActorId, ActorRoute>>>,
    invoke_routes: InvokeRoutes,
    is_role_authority: bool,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
    mut proof_producer: Option<NodeAttestationProofProducer>,
    #[cfg(all(feature = "network", feature = "storage"))] private_ingress_registration: Option<
        PrivateIngressRegistration,
    >,
    logical_timeslot: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
) -> AgentResult
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        > + Send
        + 'static,
{
    use crate::{Decode, service::ServiceWire};

    let mut error = None;
    let mut state = RootThreadState::default();
    let mut last_transport_retry = Instant::now();
    match service.catch_up() {
        Ok(true) => {
            if let Err(failure) = restore_service_root_logical_timeslot(&service, &logical_timeslot)
            {
                error!(%id, ?failure, "service root-tree startup clock restoration failed");
                error = Some(format!(
                    "service root-tree clock restoration failed: {failure}"
                ));
            }
        }
        Ok(false) => info!(%id, "service Raft root is waiting for committed service genesis"),
        Err(failure) => warn!(%id, ?failure, "service root-tree startup catch-up failed"),
    }
    while error.is_none() && !shutdown.load(Ordering::Relaxed) {
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(private_ingress) = private_ingress_registration.as_ref() {
            while let Ok(reply) = private_ingress.quiescence_receiver.try_recv() {
                let quiescent = service.private_ingress_join_quiescent().unwrap_or(false);
                let _ = reply.send(quiescent);
            }
            for _ in 0..4 {
                let Ok(upload) = private_ingress.receiver.try_recv() else {
                    break;
                };
                if !begin_service_private_ingress_upload(&upload) {
                    let _ = upload.reply.send(false);
                    continue;
                }
                let accepted = service.stage_replicated_private_ingress(
                    upload.invocation,
                    &upload.reference,
                    &upload.bytes,
                );
                let _ = upload.reply.send(accepted);
            }
        }
        while let Ok(envelope) = inbox_rx.try_recv() {
            *activity.lock().unwrap() = Instant::now();
            handle_service_root_transport(
                id,
                &root_name,
                &mut service,
                envelope,
                &outbox,
                &actor_routes,
                &invoke_routes,
                #[cfg(feature = "network")]
                &shared_network,
                &mut proof_producer,
                &logical_timeslot,
                &mut state,
            );
        }
        if last_transport_retry.elapsed() >= Duration::from_millis(250) {
            // Every Raft follower applies the same terminal ingress
            // transition. Retry host-side deletion debt without changing the
            // committed invocation's disposition.
            service.retry_private_ingress_retirement();
            retry_service_root_transport(
                id,
                &root_name,
                &mut service,
                &outbox,
                &actor_routes,
                &invoke_routes,
                #[cfg(feature = "network")]
                &shared_network,
                &mut proof_producer,
                &logical_timeslot,
                &mut state,
            );
            last_transport_retry = Instant::now();
        }
        let req = match invoke_rx.recv_timeout(Duration::from_millis(10)) {
            Ok(request) => request,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let _native_extension_chain = ServiceNativeExtensionChainGuard::stamp(&req.chain, id);
        *activity.lock().unwrap() = Instant::now();
        let ingress = match crate::service::RootTreeInvocation::decode(&req.msg) {
            Ok(ingress) => ingress,
            Err(_) => {
                send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
                continue;
            }
        };
        if ingress.target != service.root_actor() {
            send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
            continue;
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        let delegated_origin = req.delegated_origin;
        #[cfg(not(all(feature = "network", feature = "storage")))]
        let delegated_origin: Option<crate::service::Origin> = None;
        let origin = match delegated_origin {
            Some(origin) if service.consistency() == crate::service::ConsistencyMode::Raft => {
                Some(origin)
            }
            Some(_) => None,
            None => service_root_origin(&req.caller, &actor_routes),
        };
        let Some(origin) = origin else {
            send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
            continue;
        };
        if ingress.method == crate::service::ROOT_UPGRADE_METHOD_ {
            let authorized = req.root_upgrade_request
                || matches!(req.caller, crate::actors::Caller::System)
                || req.space_role.is_some_and(|role| role >= AUTH_ROLE_ADMIN);
            let upgrade = crate::service::RootTreeUpgradeRequest::decode(&ingress.arguments);
            if ingress.proof_requested || !authorized || upgrade.is_err() {
                send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                continue;
            }
            match service.upgrade_root(upgrade.expect("checked above")) {
                Ok(result) => {
                    let reply = result.encode();
                    let envelope = encode_invoke_envelope(crate::STATUS_DONE, &[], &reply);
                    let _ = send_reply_capped(req.reply, envelope, id);
                }
                Err(crate::service::LocalRootTreeInvokeError::Rejected(
                    crate::service::AccumulationRejection::Unauthorized,
                ))
                | Err(crate::service::LocalRootTreeInvokeError::UpgradeUnsupported) => {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                }
                #[cfg(all(feature = "storage", feature = "network"))]
                Err(crate::service::LocalRootTreeInvokeError::Replication(failure)) => {
                    warn!(%id, ?failure, "service root upgrade leader barrier failed");
                    if let Some(redirect) = encode_service_raft_leadership_redirect(
                        &failure,
                        service.admission_leader_hint(),
                        id.node_prefix(),
                        origin,
                        true,
                    ) {
                        let _ = send_reply_capped(req.reply, redirect, id);
                    } else {
                        send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    }
                }
                Err(failure) => {
                    error!(%id, ?failure, "service root upgrade failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                }
            }
            continue;
        }
        if ingress.arguments.first() != Some(&crate::value::TAG_DYNAMIC) {
            send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
            continue;
        }
        let Some(message) = <crate::value::Msg as Decode>::try_decode(&ingress.arguments[1..])
        else {
            send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
            continue;
        };
        if message.name != ingress.method {
            send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
            continue;
        }
        // A role check is not a sufficient leadership gate: Raft exposes
        // Leader before the promotion no-op reaches quorum. The service read
        // barrier waits for that current-term entry and catches up the complete
        // prior-term prefix before policy lookup or clock allocation.
        let admission_floor = match service.prepare_admission_barrier() {
            Ok(floor) => floor,
            Err(failure) => {
                error!(%id, ?failure, "service root-tree admission barrier failed");
                #[cfg(all(feature = "storage", feature = "network"))]
                if let crate::service::LocalRootTreeInvokeError::Replication(replication) = &failure
                    && let Some(redirect) = encode_service_raft_leadership_redirect(
                        replication,
                        service.admission_leader_hint(),
                        id.node_prefix(),
                        origin,
                        false,
                    )
                {
                    let _ = send_reply_capped(req.reply, redirect, id);
                    continue;
                }
                send_service_status(req.reply, crate::STATUS_PANICKED, id);
                continue;
            }
        };
        if ingress.proof_requested
            && (service.consistency() == crate::service::ConsistencyMode::Crdt
                || proof_producer.is_none())
        {
            send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
            continue;
        }
        let mut request = crate::service::LocalWorkRequest {
            invocation: ingress.invocation,
            workflow_step: 0,
            // Scope excludes the scheduler observation slot. Use the first
            // value above the barrier while the authority runs, then replace
            // it with the actually allocated slot immediately before admit.
            logical_timeslot: admission_floor.saturating_add(1),
            target: ingress.target,
            method: ingress.method.clone(),
            arguments: ingress.arguments.clone(),
            origin,
            authorization: crate::service::AuthorizationEvidence::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: Vec::new(),
            proof_requested: ingress.proof_requested,
        };
        let mut receipt_verifications = Vec::new();
        let recovered_authorization = match service.recover_direct_authorization(&request) {
            Ok(authorization) => authorization,
            Err(failure) => {
                warn!(%id, ?failure, "service direct invocation retry diverged");
                send_service_status(req.reply, crate::STATUS_PANICKED, id);
                continue;
            }
        };
        if let Some(authorization) = recovered_authorization {
            // A CRDT ingress is itself the guest-owned, causally finalized
            // authorization decision. Reattach that exact evidence for a
            // queued invocation or committed retry without asking the
            // authority to execute the same scoped claim again. Accumulate
            // authenticates it through the retained ingress node/receipt;
            // fresh calls still take the authority path below.
            if service.consistency() == crate::service::ConsistencyMode::Crdt {
                request.authorization = authorization;
            } else {
                match &authorization {
                    crate::service::AuthorizationEvidence::Public => {}
                    crate::service::AuthorizationEvidence::Credential {
                        policy,
                        credential_commitment,
                        bytes,
                    } => {
                        let credential = match crate::service::RoleCredential::decode(bytes) {
                            Ok(credential) => credential,
                            Err(_) => {
                                send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                                continue;
                            }
                        };
                        let assertion = match crate::service::AccumulatedRoleAssertion::decode(
                            &credential.authenticator,
                        ) {
                            Ok(assertion) => assertion,
                            Err(_) => {
                                send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                                continue;
                            }
                        };
                        let claim = &assertion.claim;
                        let Some(authority) = service.role_authority().cloned() else {
                            send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                            continue;
                        };
                        let valid = credential.commitment() == *credential_commitment
                            && credential.holder == origin
                            && credential.scope == claim.scope
                            && credential.space_role == claim.role
                            && credential.capability == claim.capability
                            && credential.actor_role.is_none()
                            && *policy == claim.policy
                            && claim.space == service.identity().space
                            && claim.holder == origin
                            && claim.audience == *service.identity()
                            && claim.invocation == ingress.invocation
                            && claim.target == ingress.target
                            && claim.method == ingress.method
                            && assertion.matches_authority(&authority);
                        if !valid {
                            send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                            continue;
                        }
                        let finalized = request_service_role_assertion(
                            &authority,
                            claim,
                            &actor_routes,
                            &invoke_routes,
                            #[cfg(feature = "network")]
                            &shared_network,
                        );
                        if finalized.as_ref() != Ok(&assertion) {
                            send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                            continue;
                        }
                        receipt_verifications.push(
                            service
                                .authorize_finalized_receipt(authority.actor, &assertion.receipt),
                        );
                    }
                    crate::service::AuthorizationEvidence::PrivateCredential { .. }
                    | crate::service::AuthorizationEvidence::SystemCapability { .. } => {
                        send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                        continue;
                    }
                }
                request.authorization = authorization;
            }
        } else {
            let policy = match service.root_method_policy(&ingress.method) {
                Ok(Some(policy)) => policy,
                Ok(None) => {
                    send_service_status(req.reply, crate::STATUS_NOT_FOUND, id);
                    continue;
                }
                Err(failure) => {
                    error!(%id, ?failure, "service root policy lookup failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                }
            };
            // Attested work and actor-local/mixed roles retain their separate
            // fail-closed paths. A space-role-only method is authorized by an
            // invocation-scoped receipt from the installed Raft authority;
            // neither raw role bytes nor synthetic System identity enter
            // the guest work envelope. CRDT ingress carries that exact scoped
            // assertion in its causal admission node, whose finalized receipt
            // is independently verified by every syncing replica.
            if policy.attested != ingress.proof_requested {
                send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                continue;
            }
            if !policy.public {
                if policy.actor_role.is_some() {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                    continue;
                }
                let role = policy.space_role.and_then(crate::SpaceRole::from_u8);
                if role.is_some() == policy.capability.is_some() {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                    continue;
                }
                let Some(authority) = service.role_authority().cloned() else {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                    continue;
                };
                let claim = match (role, policy.capability) {
                    (Some(role), None) => service.role_authorization_claim(&request, role, &policy),
                    (None, Some(capability)) => {
                        service.capability_authorization_claim(&request, capability, &policy)
                    }
                    _ => unreachable!("checked exactly one space authorization requirement"),
                };
                let claim = match claim {
                    Ok(claim) => claim,
                    Err(failure) => {
                        warn!(%id, ?failure, "could not derive service role authorization claim");
                        send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                        continue;
                    }
                };
                let assertion = match request_service_role_assertion(
                    &authority,
                    &claim,
                    &actor_routes,
                    &invoke_routes,
                    #[cfg(feature = "network")]
                    &shared_network,
                ) {
                    Ok(assertion) => assertion,
                    Err(()) => {
                        send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                        continue;
                    }
                };
                receipt_verifications
                    .push(service.authorize_finalized_receipt(authority.actor, &assertion.receipt));
                request.authorization = crate::service::RoleCredential {
                    holder: origin,
                    scope: claim.scope,
                    space_role: claim.role,
                    capability: claim.capability,
                    actor_role: None,
                    authenticator: assertion.encode(),
                }
                .disclosed_evidence(policy.policy);
            }
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        let _private_ingress_barrier = if service.consistency()
            == crate::service::ConsistencyMode::Raft
        {
            let reference = match service.private_ingress_reference_for_request(&request) {
                Ok(reference) => reference,
                Err(failure) => {
                    error!(%id, ?failure, "service private-ingress classification failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                }
            };
            if let Some(reference) = reference {
                let Some(registration) = private_ingress_registration.as_ref() else {
                    error!(%id, "service Raft private ingress has no root-owned sidecar route");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                };
                let Some(guard) = registration.route.barrier.try_acquire() else {
                    // A membership change owns the same critical section.
                    // No request has entered the log, so a normal retry is
                    // safe and cannot observe a partial admission.
                    warn!(%id, invocation = ?request.invocation, "service private-ingress admission barrier is busy");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                };
                if !stage_service_private_ingress_on_current_voters(
                    &mut service,
                    &request,
                    &reference,
                    &shared_network,
                    &invoke_routes,
                ) {
                    warn!(%id, invocation = ?request.invocation, "service private-ingress voter staging failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                }
                Some(guard)
            } else {
                None
            }
        } else {
            None
        };
        // Nothing catches up again between this allocation and the proposal.
        let final_slot = match allocate_service_root_slot_after_barrier(
            &service,
            &logical_timeslot,
            admission_floor,
        ) {
            Ok(slot) => slot,
            Err(failure) => {
                warn!(%id, ?failure, "service root-tree admission clock restoration failed");
                send_service_status(req.reply, crate::STATUS_PANICKED, id);
                if service_root_slot_failure_is_terminal(failure) {
                    error = Some(format!("service root-tree clock exhausted: {failure:?}"));
                    break;
                }
                continue;
            }
        };
        request.logical_timeslot = final_slot;
        let committed = if request.proof_requested {
            let producer = proof_producer
                .as_mut()
                .expect("attested ingress was gated on an installed producer");
            match service.invoke_attested_after_admission_barrier_with_receipts(
                request,
                &receipt_verifications,
                producer,
            ) {
                Ok(committed) => committed,
                Err(crate::service::AttestedRootTreeInvokeError::Root(
                    crate::service::LocalRootTreeInvokeError::Rejected(
                        crate::service::AccumulationRejection::Unauthorized,
                    ),
                )) => {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                    continue;
                }
                #[cfg(all(feature = "storage", feature = "network"))]
                Err(crate::service::AttestedRootTreeInvokeError::Root(
                    crate::service::LocalRootTreeInvokeError::Replication(failure),
                )) => {
                    if let Some(redirect) = encode_service_raft_leadership_redirect(
                        &failure,
                        service.admission_leader_hint(),
                        id.node_prefix(),
                        origin,
                        false,
                    ) {
                        warn!(%id, ?failure, "service attested root invocation lost leadership");
                        let _ = send_reply_capped(req.reply, redirect, id);
                    } else {
                        error!(%id, ?failure, "service attested root invocation replication failed");
                        send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    }
                    continue;
                }
                Err(failure) => {
                    error!(%id, ?failure, "service attested root invocation failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                }
            }
        } else {
            match service
                .invoke_after_admission_barrier_with_receipts(request, &receipt_verifications)
            {
                Ok(committed) => committed,
                Err(crate::service::LocalRootTreeInvokeError::Rejected(
                    crate::service::AccumulationRejection::Unauthorized,
                )) => {
                    send_service_status(req.reply, crate::STATUS_FORBIDDEN, id);
                    continue;
                }
                #[cfg(all(feature = "storage", feature = "network"))]
                Err(crate::service::LocalRootTreeInvokeError::Replication(failure)) => {
                    if let Some(redirect) = encode_service_raft_leadership_redirect(
                        &failure,
                        service.admission_leader_hint(),
                        id.node_prefix(),
                        origin,
                        false,
                    ) {
                        warn!(%id, ?failure, "service root invocation lost leadership");
                        let _ = send_reply_capped(req.reply, redirect, id);
                    } else {
                        error!(%id, ?failure, "service root invocation replication failed");
                        send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    }
                    continue;
                }
                Err(failure) => {
                    error!(%id, ?failure, "service root invocation failed");
                    send_service_status(req.reply, crate::STATUS_PANICKED, id);
                    continue;
                }
            }
        };
        let override_result = role_authority_reply_override(
            &service,
            is_role_authority && req.role_authority_request,
            &ingress,
            &committed,
        );
        publish_service_root_slice(
            id,
            &mut service,
            committed,
            Some(PendingCaller {
                reply: req.reply,
                override_result,
                attested: ingress.proof_requested,
            }),
            &outbox,
            &actor_routes,
            &mut state,
        );
    }
    actor_routes
        .write()
        .unwrap()
        .retain(|_, route| route.route != id.0);
    #[cfg(all(feature = "network", feature = "storage"))]
    if let Some(private_ingress) = private_ingress_registration.as_ref() {
        let mut routes = private_ingress.routes.write().unwrap();
        let owns_route = routes
            .get(&private_ingress.replication_id)
            .is_some_and(|route| Arc::ptr_eq(route, &private_ingress.route));
        if owns_route {
            routes.remove(&private_ingress.replication_id);
        }
    }
    AgentResult {
        id,
        panics: 0,
        error,
    }
}

fn handle_service_root_transport<B>(
    id: ServiceId,
    root_name: &str,
    service: &mut crate::service::LocalRootTreeService<B>,
    envelope: Envelope,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    invoke_routes: &InvokeRoutes,
    #[cfg(feature = "network")] shared_network: &SharedNetwork,
    proof_producer: &mut Option<NodeAttestationProofProducer>,
    logical_timeslot: &AtomicU64,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    use crate::service::ServiceWire;
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let _ = root_name;

    let transport = match crate::service::RootTreeTransport::decode(&envelope.payload) {
        Ok(transport) => transport,
        Err(failure) => {
            warn!(%id, from = %envelope.from, ?failure, "rejected non-canonical service root transport");
            return;
        }
    };
    if matches!(
        &transport,
        crate::service::RootTreeTransport::CrdtSyncChunk { .. }
            | crate::service::RootTreeTransport::CrdtSyncAccepted { .. }
    ) {
        #[cfg(all(feature = "network", feature = "storage"))]
        let authenticated = envelope
            .authenticated_source_peer
            .as_deref()
            .and_then(|peer| {
                authenticated_service_crdt_replica_peer(
                    invoke_routes,
                    peer,
                    Duration::from_millis(500),
                )
            })
            .filter(|peer| {
                crate::network::derive_node_prefix(peer) == envelope.from.node_prefix()
                    && envelope.from.local_id() == id.local_id()
                    && service_crdt_sync_peer_allowed(
                        invoke_routes,
                        peer,
                        root_name,
                        Duration::from_millis(500),
                    )
            });
        #[cfg(not(all(feature = "network", feature = "storage")))]
        let authenticated: Option<()> = None;
        if authenticated.is_none() || service.consistency() != crate::service::ConsistencyMode::Crdt
        {
            warn!(%id, from = %envelope.from, "rejected unauthenticated or misrouted service CRDT sync");
            return;
        }
        match transport {
            crate::service::RootTreeTransport::CrdtSyncChunk {
                transfer,
                chunk_index,
                chunk_count: _,
                envelope: sync_envelope,
            } => {
                if sync_envelope.service != *service.identity() {
                    warn!(%id, from = %envelope.from, "rejected CRDT chunk for another service");
                    return;
                }
                match service.sync_authenticated_crdt(sync_envelope) {
                    Ok(_) => {
                        let accepted = crate::service::RootTreeTransport::CrdtSyncAccepted {
                            service: service.identity().clone(),
                            transfer,
                            next_chunk: chunk_index.saturating_add(1),
                        };
                        let _ = outbox.send(Envelope {
                            from: id,
                            to: envelope.from,
                            payload: accepted.encode(),
                            authenticated_source_peer: None,
                            destination_peer: envelope.authenticated_source_peer.clone(),
                        });
                    }
                    Err(failure) => {
                        warn!(%id, ?failure, "guest rejected authenticated service CRDT chunk");
                    }
                }
            }
            crate::service::RootTreeTransport::CrdtSyncAccepted {
                service: accepted_service,
                transfer,
                next_chunk,
            } => {
                if accepted_service != *service.identity() {
                    warn!(%id, from = %envelope.from, "rejected CRDT acknowledgement for another service");
                    return;
                }
                #[cfg(all(feature = "network", feature = "storage"))]
                if let (Some(peer), Some(progress)) = (authenticated, state.crdt_sync.as_mut()) {
                    let key = peer.to_bytes();
                    if let Some(peer_progress) = progress.peers.get_mut(&key)
                        && peer_progress.transfer == Some(transfer)
                        && peer_progress.chunks.as_ref().is_some_and(|chunks| {
                            (next_chunk as usize) <= chunks.len()
                                && next_chunk == peer_progress.next_chunk.saturating_add(1)
                        })
                    {
                        peer_progress.next_chunk = next_chunk;
                        peer_progress.last_sent = None;
                        peer_progress.awaiting_ack_since = None;
                    }
                }
                #[cfg(not(all(feature = "network", feature = "storage")))]
                let _ = (transfer, next_chunk);
            }
            _ => unreachable!("matched CRDT transport variants above"),
        }
        return;
    }
    // Local/CRDT roots consume the authenticated route decision in one IC-5
    // call; Raft roots quorum-order the exact decision beside the delivery or
    // reply Apply entry before any follower executes it.
    if !matches!(
        service.consistency(),
        crate::service::ConsistencyMode::Local
            | crate::service::ConsistencyMode::Raft
            | crate::service::ConsistencyMode::Crdt
    ) {
        warn!(%id, from = %envelope.from, "service root transport requires a Local, Raft, or CRDT destination");
        return;
    }
    match transport {
        crate::service::RootTreeTransport::OutboxDelivery {
            publication,
            message,
        } => {
            let source = authenticated_service_actor_route_at_node(
                actor_routes,
                message.from,
                envelope.from,
                envelope.authenticated_source_peer.as_deref(),
                invoke_routes,
                #[cfg(feature = "network")]
                shared_network,
            );
            if message.to != service.root_actor()
                || message.to_service != *service.identity()
                || message.authorization != crate::service::AuthorizationEvidence::Public
                || (message.proof_requested && proof_producer.is_none())
                || (message.proof_requested
                    && (service.consistency() == crate::service::ConsistencyMode::Crdt
                        || source.as_ref().is_some_and(|source| {
                            source.consistency == crate::service::ConsistencyMode::Crdt
                        })))
                || source.as_ref().is_none_or(|source| {
                    source.service != publication.receipt.service
                        || source.service != message.from_service
                        || source.consistency != publication.receipt.consistency
                })
                || !matches!(
                    publication.receipt.consistency,
                    crate::service::ConsistencyMode::Local
                        | crate::service::ConsistencyMode::Raft
                        | crate::service::ConsistencyMode::Crdt
                )
            {
                warn!(%id, from = %envelope.from, call = ?message.call_id, "rejected unauthenticated or unsupported service delivery");
                return;
            }
            // Establish leadership/current-state readiness before consulting
            // policy or authority, but do not reserve the committed delivery
            // slot yet. A local authority invocation advances this same
            // node-wide clock and must order before the delivery.
            let admission_floor = match service.prepare_admission_barrier() {
                Ok(floor) => floor,
                Err(failure) => {
                    warn!(%id, ?failure, "service delivery admission barrier failed");
                    return;
                }
            };
            let provisional_slot = admission_floor.saturating_add(1);
            let method = if message.payload.first() == Some(&crate::value::TAG_DYNAMIC) {
                <crate::value::Msg as crate::Decode>::try_decode(&message.payload[1..])
                    .map(|message| message.name)
            } else {
                None
            };
            let Some(method) = method else {
                warn!(%id, call = ?message.call_id, "rejected non-dynamic service delivery");
                return;
            };
            let mut receipt_verifications =
                vec![service.authorize_finalized_receipt(message.from, &publication.receipt)];
            let recovered = match service.recover_delivery_authorization(
                &message,
                &publication.published.outbox,
                &publication.receipt,
            ) {
                Ok(recovered) => recovered,
                Err(failure) => {
                    warn!(%id, call = ?message.call_id, ?failure, "divergent durable delivery retry");
                    return;
                }
            };
            let authorization = if let Some(authorization) = recovered {
                match &authorization {
                    crate::service::AuthorizationEvidence::Public => {}
                    crate::service::AuthorizationEvidence::Credential { bytes, .. } => {
                        let Some(authority) = service.role_authority().cloned() else {
                            warn!(%id, call = ?message.call_id, "admitted credential lost its pinned authority");
                            return;
                        };
                        let assertion = crate::service::RoleCredential::decode(bytes)
                            .ok()
                            .and_then(|credential| {
                                crate::service::AccumulatedRoleAssertion::decode(
                                    &credential.authenticator,
                                )
                                .ok()
                            });
                        let Some(assertion) =
                            assertion.filter(|assertion| assertion.matches_authority(&authority))
                        else {
                            warn!(%id, call = ?message.call_id, "corrupt admitted delivery credential");
                            return;
                        };
                        receipt_verifications.push(
                            service
                                .authorize_finalized_receipt(authority.actor, &assertion.receipt),
                        );
                    }
                    crate::service::AuthorizationEvidence::PrivateCredential { .. }
                    | crate::service::AuthorizationEvidence::SystemCapability { .. } => {
                        warn!(%id, call = ?message.call_id, "unsupported admitted delivery credential");
                        return;
                    }
                }
                authorization
            } else {
                let policy = match service.root_method_policy(&method) {
                    Ok(Some(policy)) => policy,
                    Ok(None) => {
                        warn!(%id, call = ?message.call_id, %method, "rejected delivery to unknown method");
                        return;
                    }
                    Err(failure) => {
                        warn!(%id, call = ?message.call_id, ?failure, "could not load delivery policy");
                        return;
                    }
                };
                if policy.attested != message.proof_requested {
                    warn!(%id, call = ?message.call_id, "delivery proof mode disagrees with signed method policy");
                    return;
                }
                if policy.public {
                    crate::service::AuthorizationEvidence::Public
                } else {
                    if policy.actor_role.is_some() {
                        warn!(%id, call = ?message.call_id, "mixed durable authorization remains fail-closed");
                        return;
                    }
                    let role = policy.space_role.and_then(crate::SpaceRole::from_u8);
                    if role.is_some() == policy.capability.is_some() {
                        warn!(%id, call = ?message.call_id, "invalid durable space authorization policy");
                        return;
                    }
                    let Some(authority) = service.role_authority().cloned() else {
                        warn!(%id, call = ?message.call_id, "role-gated destination has no pinned authority");
                        return;
                    };
                    let claim = match (role, policy.capability) {
                        (Some(role), None) => service.delivery_role_authorization_claim(
                            &message,
                            role,
                            &policy,
                            provisional_slot,
                        ),
                        (None, Some(capability)) => service
                            .delivery_capability_authorization_claim(
                                &message,
                                capability,
                                &policy,
                                provisional_slot,
                            ),
                        _ => unreachable!("checked exactly one space authorization requirement"),
                    };
                    let claim = match claim {
                        Ok(claim) => claim,
                        Err(failure) => {
                            warn!(%id, call = ?message.call_id, ?failure, "could not derive delivery authorization claim");
                            return;
                        }
                    };
                    let assertion = match request_service_role_assertion(
                        &authority,
                        &claim,
                        actor_routes,
                        invoke_routes,
                        #[cfg(feature = "network")]
                        shared_network,
                    ) {
                        Ok(assertion) => assertion,
                        Err(()) => {
                            warn!(%id, call = ?message.call_id, "role authority denied durable delivery");
                            return;
                        }
                    };
                    receipt_verifications.push(
                        service.authorize_finalized_receipt(authority.actor, &assertion.receipt),
                    );
                    crate::service::RoleCredential {
                        holder: crate::service::Origin::Actor(message.from),
                        scope: claim.scope,
                        space_role: claim.role,
                        capability: claim.capability,
                        actor_role: None,
                        authenticator: assertion.encode(),
                    }
                    .disclosed_evidence(policy.policy)
                }
            };
            receipt_verifications.sort_by_key(crate::service::ReceiptVerificationRequest::hash);
            // No service catch-up or authority call may occur after this
            // allocation and before proposal. The final slot observes any
            // node-clock advancement caused by the authority execution above,
            // so deadline validation uses the true delivery order.
            let slot = match allocate_service_root_slot_after_barrier(
                service,
                logical_timeslot,
                admission_floor,
            ) {
                Ok(slot) => slot,
                Err(failure) => {
                    warn!(%id, ?failure, "could not allocate trusted service delivery slot");
                    return;
                }
            };
            let call = message.call_id;
            let commitment = publication.commitment();
            let source_service = publication.receipt.service.clone();
            match service.deliver_finalized_after_barrier(
                slot,
                authorization,
                message,
                publication.published.outbox.clone(),
                publication.receipt,
                receipt_verifications,
            ) {
                Ok(_) => {
                    let accepted = crate::service::RootTreeTransport::PublicationAccepted {
                        acceptor: service.root_actor(),
                        acceptor_service: service.identity().clone(),
                        service: source_service,
                        input: publication.input,
                        publication: commitment,
                        call,
                    };
                    let _ = outbox.send(Envelope {
                        from: id,
                        to: envelope.from,
                        payload: accepted.encode(),
                        authenticated_source_peer: None,
                        destination_peer: envelope.authenticated_source_peer.clone(),
                    });
                    run_service_root_inbox(
                        id,
                        service,
                        call,
                        outbox,
                        actor_routes,
                        proof_producer,
                        logical_timeslot,
                        state,
                    );
                }
                Err(failure) => {
                    warn!(%id, ?call, ?failure, "destination guest rejected service delivery");
                }
            }
        }
        crate::service::RootTreeTransport::Reply {
            caller,
            caller_service,
            caller_invocation,
            publication,
            proof,
        } => {
            let Some(reply) = publication.published.reply.clone() else {
                return;
            };
            let producer = authenticated_service_actor_route_at_node(
                actor_routes,
                reply.producer,
                envelope.from,
                envelope.authenticated_source_peer.as_deref(),
                invoke_routes,
                #[cfg(feature = "network")]
                shared_network,
            );
            if caller != service.root_actor()
                || caller_service != *service.identity()
                || (publication.published.attestation.is_some()
                    && (service.consistency() == crate::service::ConsistencyMode::Crdt
                        || producer.as_ref().is_some_and(|producer| {
                            producer.consistency == crate::service::ConsistencyMode::Crdt
                        })))
                || producer.as_ref().is_none_or(|producer| {
                    producer.service != publication.receipt.service
                        || producer.consistency != publication.receipt.consistency
                })
                || !matches!(
                    publication.receipt.consistency,
                    crate::service::ConsistencyMode::Local
                        | crate::service::ConsistencyMode::Raft
                        | crate::service::ConsistencyMode::Crdt
                )
            {
                warn!(%id, from = %envelope.from, call = ?reply.call_id, "rejected misrouted service reply");
                return;
            }
            let slot = match prepare_service_root_slot(service, logical_timeslot) {
                Ok(slot) => slot,
                Err(failure) => {
                    warn!(%id, ?failure, "could not allocate trusted service reply slot");
                    return;
                }
            };
            let accumulated = crate::service::AccumulatedReply {
                reply: reply.clone(),
                receipt: publication.receipt.clone(),
                attestation: publication.published.attestation.clone(),
            };
            // Authenticate this exact physical receipt from the bound source
            // route before consulting logical reply admission. A convergent
            // alternate CRDT branch may skip actor execution, but it cannot
            // inherit another branch's verifier decision.
            let receipt_verification =
                service.authorize_finalized_receipt(reply.producer, &publication.receipt);
            let already = match service.reply_already_accumulated(caller_invocation, &accumulated) {
                Ok(already) => already,
                Err(failure) => {
                    warn!(%id, ?failure, "could not inspect durable service reply admission");
                    return;
                }
            };
            let committed = if already {
                None
            } else {
                match service.resume_reply_after_barrier(
                    caller_invocation,
                    slot,
                    accumulated,
                    proof,
                    receipt_verification,
                ) {
                    Ok(committed) => Some(committed),
                    Err(failure) => {
                        warn!(%id, ?failure, "caller guest rejected finalized service reply");
                        return;
                    }
                }
            };
            let accepted = crate::service::RootTreeTransport::PublicationAccepted {
                acceptor: service.root_actor(),
                acceptor_service: service.identity().clone(),
                service: publication.receipt.service.clone(),
                input: publication.input,
                publication: publication.commitment(),
                call: reply.call_id,
            };
            let _ = outbox.send(Envelope {
                from: id,
                to: envelope.from,
                payload: accepted.encode(),
                authenticated_source_peer: None,
                destination_peer: envelope.authenticated_source_peer.clone(),
            });
            if let Some(committed) = committed {
                publish_service_root_slice(
                    id,
                    service,
                    committed,
                    None,
                    outbox,
                    actor_routes,
                    state,
                );
            }
        }
        crate::service::RootTreeTransport::PublicationAccepted {
            acceptor,
            acceptor_service,
            service: acknowledged_service,
            input,
            publication,
            call,
        } => {
            if service.consistency() == crate::service::ConsistencyMode::Raft
                && service.prepare_admission_barrier().is_err()
            {
                // Progress is deliberately rebuilt by the current leader from
                // durable publications and duplicate destination admissions.
                // A follower must never retain process-local acknowledgement
                // state which its leader cannot observe.
                return;
            }
            acknowledge_service_root_publication(
                id,
                service,
                envelope.from,
                envelope.authenticated_source_peer.as_deref(),
                input,
                acceptor,
                acceptor_service,
                acknowledged_service,
                publication,
                call,
                outbox,
                actor_routes,
                invoke_routes,
                #[cfg(feature = "network")]
                shared_network,
                state,
            )
        }
        crate::service::RootTreeTransport::CrdtSyncChunk { .. }
        | crate::service::RootTreeTransport::CrdtSyncAccepted { .. } => {
            unreachable!("CRDT transport returned from its fail-closed early handler")
        }
    }
}

fn publish_service_root_slice<B>(
    id: ServiceId,
    service: &mut crate::service::LocalRootTreeService<B>,
    committed: crate::service::CommittedRootTreeSlice,
    caller: Option<PendingCaller>,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let committed_attested = committed.recovered_result.as_ref().map_or_else(
        || committed.published.attestation.is_some(),
        |result| result.attested,
    );
    if caller
        .as_ref()
        .is_some_and(|caller| caller.attested != committed_attested)
    {
        send_service_status(
            caller.expect("checked above").reply,
            crate::STATUS_PANICKED,
            id,
        );
        return;
    }
    if let Some(caller) = caller {
        state
            .pending_callers
            .entry(committed.input.invocation)
            .or_default()
            .push(caller);
    }
    let recovered_reply = committed
        .published
        .reply
        .as_ref()
        .map(|reply| reply.result.as_slice());
    let recovered_result = committed.recovered_result.as_ref();
    let Some(publication) = committed.publication else {
        if committed.duplicate
            && let Some(callers) = state.pending_callers.remove(&committed.input.invocation)
        {
            for caller in callers {
                match caller.override_result {
                    Some(Ok(result)) => {
                        let _ = send_reply_capped(
                            caller.reply,
                            encode_invoke_envelope(crate::STATUS_DONE, &[], &result),
                            id,
                        );
                    }
                    Some(Err(status)) => send_service_status(caller.reply, status, id),
                    None if recovered_result.is_some() => {
                        let result = recovered_result.expect("checked above");
                        let _ = send_reply_capped(
                            caller.reply,
                            encode_invoke_envelope(crate::STATUS_DONE, &[], &result.bytes),
                            id,
                        );
                    }
                    None if caller.attested => {
                        match encode_service_attested_result(service, &committed.published) {
                            Some(result) => {
                                let _ = send_reply_capped(
                                    caller.reply,
                                    encode_invoke_envelope(crate::STATUS_DONE, &[], &result),
                                    id,
                                );
                            }
                            None => send_service_status(caller.reply, crate::STATUS_PANICKED, id),
                        }
                    }
                    None => match recovered_reply {
                        Some(result) => {
                            let _ = send_reply_capped(
                                caller.reply,
                                encode_invoke_envelope(crate::STATUS_DONE, &[], result),
                                id,
                            );
                        }
                        None => send_service_status(caller.reply, crate::STATUS_PANICKED, id),
                    },
                }
            }
        }
        return;
    };
    queue_service_root_publication(id, service, &publication, outbox, actor_routes, state);
}

fn queue_service_root_publication<B>(
    id: ServiceId,
    service: &mut crate::service::LocalRootTreeService<B>,
    publication: &crate::service::PublicationRecord,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    use crate::service::ServiceWire;

    if publication.receipt.service != *service.identity() {
        warn!(%id, "ignored a publication owned by another service root");
        return;
    }
    let ordinary_transport = matches!(
        service.consistency(),
        crate::service::ConsistencyMode::Local
            | crate::service::ConsistencyMode::Raft
            | crate::service::ConsistencyMode::Crdt
    ) && publication.receipt.consistency == service.consistency();
    if ordinary_transport {
        for message in &publication.published.outbox {
            let Some(route) = service_actor_route(actor_routes, message.to) else {
                continue;
            };
            if route.service != message.to_service
                || !matches!(
                    route.consistency,
                    crate::service::ConsistencyMode::Local
                        | crate::service::ConsistencyMode::Raft
                        | crate::service::ConsistencyMode::Crdt
                )
            {
                continue;
            }
            let transport = crate::service::RootTreeTransport::OutboxDelivery {
                publication: publication.clone(),
                message: message.clone(),
            };
            let _ = outbox.send(Envelope {
                from: id,
                to: ServiceId(route.route),
                payload: transport.encode(),
                authenticated_source_peer: None,
                destination_peer: route.authenticated_peer.clone(),
            });
        }
    } else if !publication.published.outbox.is_empty() {
        warn!(%id, "retained a non-Local/Raft/CRDT outbox publication outside ordinary root transport");
    }

    // A direct caller channel is process-local. Do not expose its reply while
    // the same publication still has durable outbox consumers: a crash in
    // between would forget that ephemeral acceptance and leave the retained
    // publication permanently unreclaimable. Remote replies also follow this
    // ordering, keeping one uniform publication state machine.
    let commitment = publication.commitment();
    let calls_done = publication.published.outbox.iter().all(|message| {
        state
            .publication_progress
            .get(&commitment)
            .is_some_and(|progress| progress.accepted_calls.contains(&message.call_id))
    });
    if !calls_done {
        return;
    }

    let Some(reply) = publication.published.reply.as_ref() else {
        maybe_ack_service_root_publication(id, service, publication, state);
        return;
    };
    if state
        .publication_progress
        .get(&commitment)
        .is_some_and(|progress| progress.reply_accepted)
    {
        // A direct caller may have accepted the reply just before a durable
        // publication acknowledgement failed. The caller channel is already
        // gone, so retries must drive the acknowledgement from durable
        // publication state rather than trying to deliver the reply again.
        maybe_ack_service_root_publication(id, service, publication, state);
        return;
    }
    let mut accepted = false;
    if let Some(callers) = state.pending_callers.remove(&publication.input.invocation) {
        for caller in callers {
            let envelope = match caller.override_result {
                Some(Ok(result)) => encode_invoke_envelope(crate::STATUS_DONE, &[], &result),
                Some(Err(status)) => encode_invoke_envelope(status, &[], &[]),
                None if caller.attested => {
                    let Some(result) =
                        encode_service_attested_result(service, &publication.published)
                    else {
                        send_service_status(caller.reply, crate::STATUS_PANICKED, id);
                        continue;
                    };
                    encode_invoke_envelope(crate::STATUS_DONE, &[], &result)
                }
                None => encode_invoke_envelope(crate::STATUS_DONE, &[], &reply.result),
            };
            accepted |= send_reply_capped(caller.reply, envelope, id);
        }
    } else {
        match service.publication_return_target(publication) {
            Ok(Some((actor, caller_service, caller_invocation))) => {
                if ordinary_transport && let Some(route) = service_actor_route(actor_routes, actor)
                {
                    if route.service != caller_service
                        || !matches!(
                            route.consistency,
                            crate::service::ConsistencyMode::Local
                                | crate::service::ConsistencyMode::Raft
                                | crate::service::ConsistencyMode::Crdt
                        )
                    {
                        return;
                    }
                    let transport = crate::service::RootTreeTransport::Reply {
                        caller: actor,
                        caller_service,
                        caller_invocation,
                        publication: publication.clone(),
                        proof: publication.published.attestation.as_deref().and_then(
                            |attestation| service.attestation_proof(&attestation.proof.proof_blob),
                        ),
                    };
                    if publication.published.attestation.is_some()
                        && matches!(
                            &transport,
                            crate::service::RootTreeTransport::Reply { proof: None, .. }
                        )
                    {
                        warn!(%id, "retained attested reply whose proof artifact is unavailable");
                        return;
                    }
                    let _ = outbox.send(Envelope {
                        from: id,
                        to: ServiceId(route.route),
                        payload: transport.encode(),
                        authenticated_source_peer: None,
                        destination_peer: route.authenticated_peer.clone(),
                    });
                    // Sending a remote reply is not acceptance; only the
                    // destination's guest-commit acknowledgement retires it.
                }
            }
            Ok(None) => {}
            Err(failure) => warn!(%id, ?failure, "could not recover service reply return route"),
        }
    }
    if accepted {
        state
            .publication_progress
            .entry(publication.commitment())
            .or_default()
            .reply_accepted = true;
        maybe_ack_service_root_publication(id, service, publication, state);
    }
}

fn encode_service_attested_result<B>(
    service: &crate::service::LocalRootTreeService<B>,
    published: &crate::service::PublishedEffects,
) -> Option<Vec<u8>>
where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    use crate::service::ServiceWire;

    let reply = published.reply.as_ref()?;
    let attestation = published.attestation.as_deref()?.clone();
    if published.proof.as_ref() != Some(&attestation.proof) {
        return None;
    }
    let proof = service.attestation_proof(&attestation.proof.proof_blob)?;
    let result = crate::service::RootTreeAttestedResult {
        reply: reply.result.clone(),
        attestation,
        proof: proof.bytes,
    };
    result.validate().ok()?;
    Some(result.encode())
}

fn maybe_ack_service_root_publication<B>(
    id: ServiceId,
    service: &mut crate::service::LocalRootTreeService<B>,
    publication: &crate::service::PublicationRecord,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let commitment = publication.commitment();
    let progress = state.publication_progress.entry(commitment).or_default();
    let calls_done = publication
        .published
        .outbox
        .iter()
        .all(|message| progress.accepted_calls.contains(&message.call_id));
    let reply_done = publication.published.reply.is_none() || progress.reply_accepted;
    if calls_done && reply_done {
        match service.acknowledge_publication(publication) {
            Ok(_) => {
                state.publication_progress.remove(&commitment);
            }
            Err(failure) => warn!(%id, ?failure, "service publication acknowledgement failed"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn acknowledge_service_root_publication<B>(
    id: ServiceId,
    service: &mut crate::service::LocalRootTreeService<B>,
    from: ServiceId,
    authenticated_peer: Option<&[u8]>,
    input: crate::service::WorkInputId,
    acceptor: crate::service::ActorId,
    acceptor_service: crate::service::ServiceIdentity,
    acknowledged_service: crate::service::ServiceIdentity,
    commitment: crate::service::Hash,
    call: crate::service::CallId,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    invoke_routes: &InvokeRoutes,
    #[cfg(feature = "network")] shared_network: &SharedNetwork,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let Some(publication) = service.pending_publications().ok().and_then(|pending| {
        pending.into_iter().find(|candidate| {
            candidate.input == input
                && candidate.commitment() == commitment
                && candidate.receipt.service == acknowledged_service
        })
    }) else {
        return;
    };
    let progress = state.publication_progress.entry(commitment).or_default();
    if let Some(message) = publication
        .published
        .outbox
        .iter()
        .find(|message| message.call_id == call)
    {
        if acceptor != message.to || acceptor_service != message.to_service {
            return;
        }
        if authenticated_service_actor_route_at_node(
            actor_routes,
            acceptor,
            from,
            authenticated_peer,
            invoke_routes,
            #[cfg(feature = "network")]
            shared_network,
        )
        .is_some_and(|route| {
            route.service == message.to_service
                && matches!(
                    route.consistency,
                    crate::service::ConsistencyMode::Local
                        | crate::service::ConsistencyMode::Raft
                        | crate::service::ConsistencyMode::Crdt
                )
        }) {
            progress.accepted_calls.insert(call);
        } else {
            return;
        }
    } else if publication
        .published
        .reply
        .as_ref()
        .is_some_and(|reply| reply.call_id == call)
    {
        let expected = service
            .publication_return_target(&publication)
            .ok()
            .flatten()
            .and_then(|(actor, service, _)| {
                if acceptor != actor || acceptor_service != service {
                    return None;
                }
                authenticated_service_actor_route_at_node(
                    actor_routes,
                    actor,
                    from,
                    authenticated_peer,
                    invoke_routes,
                    #[cfg(feature = "network")]
                    shared_network,
                )
                .filter(|route| {
                    route.service == service
                        && matches!(
                            route.consistency,
                            crate::service::ConsistencyMode::Local
                                | crate::service::ConsistencyMode::Raft
                                | crate::service::ConsistencyMode::Crdt
                        )
                })
            });
        if expected.is_none() {
            return;
        }
        progress.reply_accepted = true;
    } else {
        return;
    }
    let calls_done = publication
        .published
        .outbox
        .iter()
        .all(|message| progress.accepted_calls.contains(&message.call_id));
    let reply_done = publication.published.reply.is_none() || progress.reply_accepted;
    if calls_done && !reply_done {
        queue_service_root_publication(id, service, &publication, outbox, actor_routes, state);
        return;
    }
    if calls_done && reply_done {
        match service.acknowledge_publication(&publication) {
            Ok(_) => {
                state.publication_progress.remove(&commitment);
            }
            Err(failure) => warn!(%id, ?failure, "service publication acknowledgement failed"),
        }
    }
}

fn run_service_root_inbox<B>(
    id: ServiceId,
    service: &mut crate::service::LocalRootTreeService<B>,
    call: crate::service::CallId,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    proof_producer: &mut Option<NodeAttestationProofProducer>,
    logical_timeslot: &AtomicU64,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    let slot = match prepare_service_root_slot(service, logical_timeslot) {
        Ok(slot) => slot,
        Err(failure) => {
            warn!(%id, ?failure, "could not allocate trusted service inbox slot");
            return;
        }
    };
    let result = match service.invoke_inbox_after_barrier(call, slot) {
        Err(crate::service::LocalRootTreeInvokeError::ProofProducerRequired) => {
            let Some(producer) = proof_producer.as_mut() else {
                return;
            };
            match service.invoke_attested_inbox_after_barrier(call, slot, producer) {
                Ok(committed) => Ok(committed),
                Err(crate::service::AttestedRootTreeInvokeError::Root(error)) => Err(error),
                Err(failure) => {
                    warn!(%id, ?call, ?failure, "service attested inbox execution failed");
                    return;
                }
            }
        }
        result => result,
    };
    match result {
        Ok(committed) => {
            publish_service_root_slice(id, service, committed, None, outbox, actor_routes, state)
        }
        Err(crate::service::LocalRootTreeInvokeError::Schedule(
            crate::service::ScheduleError::DeadlineExpired(_),
        )) => {
            if let Err(failure) = service.retire_inbox_after_barrier(call, slot) {
                warn!(%id, ?call, ?failure, "service expired inbox retirement failed");
            }
        }
        Err(crate::service::LocalRootTreeInvokeError::Schedule(
            crate::service::ScheduleError::ActorBusy(_)
            | crate::service::ScheduleError::MissingInbox(_),
        )) => {}
        Err(failure) => warn!(%id, ?call, ?failure, "service admitted inbox execution failed"),
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
fn advertise_service_crdt_root<B>(
    id: ServiceId,
    root_name: &str,
    service: &crate::service::LocalRootTreeService<B>,
    outbox: &mpsc::Sender<Envelope>,
    invoke_routes: &InvokeRoutes,
    shared_network: &SharedNetwork,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    use crate::service::ServiceWire;

    const RETRY: Duration = Duration::from_secs(5);
    const ROSTER_BUDGET: Duration = Duration::from_millis(250);
    const AUTH_BUDGET: Duration = Duration::from_millis(500);

    if service.consistency() != crate::service::ConsistencyMode::Crdt {
        return;
    }
    let commitment = match service.crdt_frontier_commitment() {
        Ok(Some(commitment)) => commitment,
        Ok(None) => return,
        Err(failure) => {
            warn!(%id, ?failure, "could not identify canonical service CRDT frontier");
            return;
        }
    };
    let now = Instant::now();
    if state
        .crdt_sync
        .as_ref()
        .is_none_or(|progress| progress.latest_frontier != commitment)
    {
        let envelope = match service.crdt_sync_envelope() {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return,
            Err(failure) => {
                warn!(%id, ?failure, "could not export canonical service CRDT frontier");
                return;
            }
        };
        let (transfer, chunks) =
            match service_crdt_sync_chunks(envelope, SERVICE_CRDT_SYNC_CHUNK_MAX_BYTES) {
                Ok(chunks) => chunks,
                Err(failure) => {
                    warn!(%id, %failure, "could not split canonical service CRDT frontier");
                    return;
                }
            };
        if let Some(progress) = state.crdt_sync.as_mut() {
            // A local write only replaces the newest offered snapshot. Every
            // peer retains its immutable transfer and acknowledgement index;
            // roster pagination and fair fan-out continue uninterrupted.
            progress.replace_latest(commitment, transfer, chunks);
        } else {
            state.crdt_sync = Some(CrdtSyncProgress {
                latest_frontier: commitment,
                latest_transfer: transfer,
                latest_chunks: Arc::new(chunks),
                peers: HashMap::new(),
                roster_seen: HashSet::new(),
                roster_after_kind: crate::registry::MEMBER_KIND_NODE,
                roster_after_key: Vec::new(),
                next_roster_page: now,
                fanout_after: None,
            });
        }
    }
    let Some(network) = shared_network
        .lock()
        .ok()
        .and_then(|network| network.clone())
    else {
        return;
    };
    let local_peer = network.peer_id();
    let Some(progress) = state.crdt_sync.as_mut() else {
        return;
    };

    // Drain one registry page per drive. Completed pages immediately become
    // eligible recipients; a 1,025th node is reached on the 17th drive rather
    // than making every attempt discard the first 1,024 rows.
    if now >= progress.next_roster_page {
        match service_crdt_replica_roster_page(
            invoke_routes,
            progress.roster_after_kind,
            progress.roster_after_key.clone(),
            ROSTER_BUDGET,
        ) {
            Some(page) => {
                for peer in page.peers {
                    if peer != local_peer {
                        let peer = peer.to_bytes();
                        progress.roster_seen.insert(peer.clone());
                        progress.peers.entry(peer).or_default();
                    }
                }
                if let Some((kind, key)) = page.next {
                    progress.roster_after_kind = kind;
                    progress.roster_after_key = key;
                    progress.next_roster_page = now;
                } else {
                    progress.finish_roster_scan();
                    progress.roster_after_kind = crate::registry::MEMBER_KIND_NODE;
                    progress.roster_after_key.clear();
                    progress.next_roster_page = now + RETRY;
                }
            }
            None => progress.next_roster_page = now + Duration::from_secs(1),
        }
    }

    let latest_transfer = progress.latest_transfer;
    let latest_chunks = progress.latest_chunks.clone();
    let peers = service_crdt_fanout_order(
        progress
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.needs_transfer(latest_transfer)
                    && peer
                        .last_sent
                        .is_none_or(|last| now.duration_since(last) >= RETRY)
            })
            .map(|(peer, _)| peer.clone())
            .collect(),
        progress.fanout_after.as_deref(),
    );
    for peer_bytes in peers.into_iter().take(SERVICE_CRDT_SYNC_ATTEMPT_BUDGET) {
        // Advance before the blocking probes. Rejection, timeout, malformed
        // registry data and send failure all consume one bounded attempt and
        // cannot make this peer monopolize the next drive.
        progress.fanout_after = Some(peer_bytes.clone());
        let Some(peer_progress) = progress.peers.get_mut(&peer_bytes) else {
            continue;
        };
        let Some(peer) =
            authenticated_service_crdt_replica_peer(invoke_routes, &peer_bytes, AUTH_BUDGET)
        else {
            peer_progress.release_transfer();
            peer_progress.last_sent = Some(now);
            continue;
        };
        if peer == local_peer
            || !service_crdt_sync_peer_allowed(invoke_routes, &peer, root_name, AUTH_BUDGET)
        {
            peer_progress.release_transfer();
            peer_progress.last_sent = Some(now);
            continue;
        }
        peer_progress.release_stalled_transfer(now, SERVICE_CRDT_SYNC_TRANSFER_STALL);
        service_crdt_select_latest_peer_transfer(peer_progress, latest_transfer, &latest_chunks);
        let Some(transfer) = peer_progress.transfer else {
            continue;
        };
        let Some(chunks) = peer_progress.chunks.as_ref() else {
            continue;
        };
        let Some(chunk) = chunks.get(peer_progress.next_chunk as usize) else {
            continue;
        };
        let chunk_count = chunks.len() as u32;
        let payload = crate::service::RootTreeTransport::CrdtSyncChunk {
            transfer,
            chunk_index: peer_progress.next_chunk,
            chunk_count,
            envelope: chunk.clone(),
        }
        .encode();
        if payload.len() > SERVICE_CRDT_SYNC_CHUNK_MAX_BYTES {
            warn!(%id, bytes = payload.len(), "refused oversized service CRDT transport chunk");
            continue;
        }
        let to = ServiceId::new(crate::network::derive_node_prefix(&peer), id.local_id());
        if outbox
            .send(Envelope {
                from: id,
                to,
                payload,
                authenticated_source_peer: None,
                destination_peer: Some(peer.to_bytes()),
            })
            .is_ok()
        {
            peer_progress.awaiting_ack_since.get_or_insert(now);
            peer_progress.last_sent = Some(now);
        }
    }
}

fn retry_service_root_transport<B>(
    id: ServiceId,
    root_name: &str,
    service: &mut crate::service::LocalRootTreeService<B>,
    outbox: &mpsc::Sender<Envelope>,
    actor_routes: &RwLock<HashMap<crate::service::ActorId, ActorRoute>>,
    invoke_routes: &InvokeRoutes,
    #[cfg(feature = "network")] shared_network: &SharedNetwork,
    proof_producer: &mut Option<NodeAttestationProofProducer>,
    logical_timeslot: &AtomicU64,
    state: &mut RootThreadState,
) where
    B: crate::service::CommittedImageStore
        + crate::service::ProofArtifactStore<
            Error = <B as crate::service::CommittedImageStore>::Error,
        >,
{
    match service.catch_up() {
        Ok(true) => {}
        Ok(false) | Err(_) => return,
    }
    #[cfg(all(feature = "network", feature = "storage"))]
    advertise_service_crdt_root(
        id,
        root_name,
        service,
        outbox,
        invoke_routes,
        shared_network,
        state,
    );
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let _ = (invoke_routes, root_name);
    let observed_timeslot = match service.production_logical_timeslot() {
        Ok(Some(slot)) => Some(slot),
        Ok(None) => Some(
            logical_timeslot
                .load(Ordering::Relaxed)
                .max(service_wall_timeslot()),
        ),
        Err(failure) => {
            warn!(%id, ?failure, "production service platform timeslot is unavailable");
            None
        }
    };
    let should_expire = service
        .next_pending_call_deadline()
        .ok()
        .flatten()
        .is_some_and(|deadline| observed_timeslot.is_some_and(|slot| slot >= deadline));
    if should_expire {
        match prepare_service_root_slot(service, logical_timeslot) {
            Ok(expiration_slot) => {
                if let Err(failure) = service.expire_due_calls_after_barrier(expiration_slot) {
                    // Earlier expirations in the same drive may already be
                    // durable. Continue into outcome rediscovery instead of
                    // losing those workflows with the returned error.
                    warn!(%id, ?failure, "service durable call expiration failed");
                }
            }
            Err(failure) => {
                warn!(%id, ?failure, "could not allocate trusted service expiration slot");
            }
        }
    }
    let pending_timeouts = match service.pending_timeout_resumes() {
        Ok(pending) => pending,
        Err(failure) => {
            warn!(%id, ?failure, "could not rediscover durable service timeout outcomes");
            Vec::new()
        }
    };
    for invocation in pending_timeouts {
        let resume_slot = match prepare_service_root_slot(service, logical_timeslot) {
            Ok(slot) => slot,
            Err(failure) => {
                warn!(%id, ?failure, ?invocation, "could not allocate service timeout-resume slot");
                continue;
            }
        };
        match service.resume_timeout_after_barrier(invocation, resume_slot) {
            Ok(Some(committed)) => publish_service_root_slice(
                id,
                service,
                committed,
                None,
                outbox,
                actor_routes,
                state,
            ),
            Ok(None) => {}
            Err(failure) => {
                warn!(%id, ?failure, ?invocation, "service timed-out workflow resume failed")
            }
        }
    }
    if let Ok(publications) = service.pending_publications()
        && (!publications.is_empty()
            && (service.consistency() != crate::service::ConsistencyMode::Raft
                || service.prepare_admission_barrier().is_ok()))
    {
        // Only the current source leader redrives Raft publications. After a
        // failover it starts with empty process-local progress, replays every
        // durable publication, and learns prior admissions from the
        // destinations' duplicate acknowledgements.
        for publication in publications {
            queue_service_root_publication(id, service, &publication, outbox, actor_routes, state);
        }
    }
    if matches!(
        service.consistency(),
        crate::service::ConsistencyMode::Local
            | crate::service::ConsistencyMode::Raft
            | crate::service::ConsistencyMode::Crdt
    ) && let Ok(pending) = service.pending_inbox_calls()
    {
        for (call, _) in pending {
            run_service_root_inbox(
                id,
                service,
                call,
                outbox,
                actor_routes,
                proof_producer,
                logical_timeslot,
                state,
            );
        }
    }
    if let Ok(pending) = service.pending_ingresses() {
        for ingress in pending {
            let result = if ingress.proof_requested {
                let Some(producer) = proof_producer.as_mut() else {
                    continue;
                };
                match service.invoke_admitted_attested(ingress.invocation, producer) {
                    Ok(committed) => Ok(committed),
                    Err(crate::service::AttestedRootTreeInvokeError::Root(error)) => Err(error),
                    Err(failure) => {
                        warn!(%id, ?failure, "service queued attested ingress retry failed");
                        continue;
                    }
                }
            } else {
                service.invoke_admitted(ingress.invocation)
            };
            match result {
                Ok(committed) => publish_service_root_slice(
                    id,
                    service,
                    committed,
                    None,
                    outbox,
                    actor_routes,
                    state,
                ),
                Err(crate::service::LocalRootTreeInvokeError::Schedule(
                    crate::service::ScheduleError::ActorBusy(_),
                )) => {}
                Err(failure) => warn!(%id, ?failure, "service queued ingress retry failed"),
            }
        }
    }
}

// ── Agent thread ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
// `config` is mutated only on the CRDT/Raft pre-open path (gated
// all(storage, network)); without both, the `mut` is unused.
#[cfg_attr(not(all(feature = "storage", feature = "network")), allow(unused_mut))]
fn agent_thread(
    id: ServiceId,
    mut config: AgentConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    agent_names: AgentNames,
    raft_fwd: RaftFwd,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
    #[cfg(all(feature = "network", feature = "storage"))] sync_rx: Option<mpsc::Receiver<()>>,
) -> AgentResult {
    use std::collections::VecDeque;

    let mut runtime = VosRuntime::new();
    let bump = || *activity.lock().unwrap() = Instant::now();

    // The chain of ServiceIds currently on the synchronous-invoke
    // stack leading to this thread, including this agent itself.
    // Updated at the entry of every dispatch and read by the
    // `external_invoke` closure to short-circuit cycles and cap
    // total depth. Wrapped in Arc<Mutex<...>> rather than
    // Rc<RefCell<...>> so the closure satisfies the `Send` bound
    // on `ExternalInvokeFn`.
    let current_chain: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    // External invoke handler for ctx.ask targets that live on a
    // different thread (workers OR other agents). Looks up the
    // target's invoke channel in the shared route table and
    // blocks on the reply, with two safety checks first:
    //
    //   - Cycle: if `target` already appears in the current chain,
    //     forwarding would deadlock. Abort with `None`, which
    //     surfaces to the caller's PVM as `InvokeError::NotFound`.
    //   - Depth: cap at MAX_CROSS_AGENT_DEPTH hops. Same abort.
    let invoke_routes_for_ext = invoke_routes.clone();
    let chain_for_ext = current_chain.clone();
    // Resolve each target's name and relay only authority explicitly granted
    // by `intra_caps`.
    let agent_names_for_ext = agent_names.clone();
    let intra_caps_for_ext = config.intra_caps.clone();
    #[cfg(feature = "network")]
    let shared_network_for_ext = shared_network.clone();
    // Only the cross-node routing branch (network) reads this.
    #[cfg(feature = "network")]
    let local_prefix = id.node_prefix();
    runtime.set_external_invoke(Box::new(move |target, msg| {
        let chain_snapshot = chain_for_ext.lock().ok()?.clone();

        match check_invoke_forward(&chain_snapshot, target.0) {
            InvokeForwardCheck::Allowed => {}
            InvokeForwardCheck::Cycle => {
                warn!(
                    target = target.0,
                    chain = ?chain_snapshot,
                    "cross-agent invoke would form a cycle; aborting forward",
                );
                return None;
            }
            InvokeForwardCheck::DepthExceeded => {
                warn!(
                    depth = chain_snapshot.len(),
                    cap = MAX_CROSS_AGENT_DEPTH,
                    "cross-agent invoke chain exceeded depth cap; aborting forward",
                );
                return None;
            }
        }

        // 1. Local invoke route — same node, agent or worker.
        let local_tx = {
            let map = invoke_routes_for_ext.lock().ok()?;
            map.get(&target.0).cloned()
        };
        if let Some(tx) = local_tx {
            let target_name = agent_names_for_ext
                .read()
                .ok()
                .and_then(|m| m.get(&local_id_of(target.0)).cloned());
            let propagated = current_relay_caller();
            let (caller, space_role) = resolve_relay_caller(
                propagated.as_ref(),
                &intra_caps_for_ext,
                target_name.as_deref(),
                Some(id),
            );
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                caller,
                space_role,
                actor_local_role: None,
                #[cfg(all(feature = "network", feature = "storage"))]
                delegated_origin: None,
                role_authority_request: false,
                root_upgrade_request: false,
                invocation_id: None,
                native_call: None,
                msg: msg.to_vec(),
                reply: ReplyChannel::Sync(reply_tx),
                chain: chain_snapshot,
            })
            .ok()?;
            // The receiver replies with the full invoke envelope;
            // unpack it back to (status, state, reply) so the
            // runtime can repack into the local invoke wire format
            // — preserving STATUS_YIELDED across the thread
            // boundary so the calling actor can keep driving a
            // yielded child.
            match reply_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(envelope) => {
                    #[cfg(all(feature = "network", feature = "storage"))]
                    if let Some(redirect) = decode_service_raft_redirect(&envelope)
                        && let Some(rep_id) = raft_forward_plan(&raft_fwd, id, target.0)
                    {
                        return agent_forward_to_raft_leader(
                            &raft_fwd,
                            id,
                            target.0,
                            rep_id,
                            msg.to_vec(),
                            Some(redirect.origin),
                        )
                        .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                    return decode_invoke_envelope(&envelope);
                }
                // The local target dropped its reply sender — the signature of
                // a raft follower refusing a write. If it is a raft agent,
                // forward the write to the leader (the agent analogue of the
                // extension ask path's `route_invoke` leader-forward).
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    #[cfg(all(feature = "network", feature = "storage"))]
                    if let Some(rep_id) = raft_forward_plan(&raft_fwd, id, target.0) {
                        return agent_forward_to_raft_leader(
                            &raft_fwd,
                            id,
                            target.0,
                            rep_id,
                            msg.to_vec(),
                            None,
                        )
                        .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                    return None;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
            }
        }

        // 2. Cross-node invoke — target on a different node and we
        //    have a `Network` attached. Reuses the chain so the
        //    far side detects cycles that span multiple hosts.
        //
        // The libp2p protocol still ships only reply bytes (no
        // YIELDED/state plumbing across the wire yet), so we wrap
        // them in a DONE envelope here. A future protocol bump
        // can carry the full envelope so cross-node yielded
        // children are drivable too.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(local_prefix) && !target.is_local() {
                let net = shared_network_for_ext.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net {
                    let prefix = target.node_prefix();
                    if let Some(peer) = net.peer_for_prefix(prefix) {
                        let reply_rx =
                            net.send_invoke(peer, id.0, target.0, chain_snapshot, msg.to_vec());
                        return reply_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .ok()
                            .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                }
            }
        }

        None
    }));

    let consistency = config.consistency;
    // Recording captures the per-dispatch `EffectLog` payload the
    // strategy needs to replay deterministically on cold start.
    // Both replicating strategies want it; the non-replicating ones
    // ignore the log if handed.
    let recording_enabled = matches!(consistency, Consistency::Crdt | Consistency::Raft,);
    // Capture rep_id up front — config is consumed below.
    #[cfg(all(feature = "network", feature = "storage"))]
    let agent_rep_id: Option<[u8; 32]> = config.replication_id;
    // Multi-mode Raft: register() pre-spawned the worker and
    // handed it to us through the config; build the Multi-flavour
    // strategy here while we still own `config` mutably.
    #[cfg(all(feature = "network", feature = "storage"))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> =
        if consistency == Consistency::Raft && config.raft_worker.is_some() {
            let db = config.pre_opened_db.clone();
            let worker = config.raft_worker.take();
            let apply_rx = config.raft_apply_rx.take();
            match (db, worker, apply_rx) {
                (Some(db), Some(worker), Some(apply_rx)) => {
                    let cfg = crate::raft::RaftConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: agent_rep_id.unwrap_or([0u8; 32]),
                        ..crate::raft::RaftConfig::default()
                    };
                    match crate::raft::RaftCommit::from_worker(db, cfg, worker, apply_rx) {
                        Ok(s) => Some(Box::new(s) as Box<dyn crate::commit::CommitStrategy>),
                        Err(e) => {
                            error!(%id, error = %e, "raft multi: failed to construct strategy");
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        };
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> = None;
    let mut strategy: Box<dyn crate::commit::CommitStrategy> = match raft_multi {
        Some(s) => s,
        None => match build_agent_strategy(&config, id, id.node_prefix()) {
            Ok(s) => s,
            Err(e) => {
                let err = format!("strategy build failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: 0,
                    error: Some(err),
                };
            }
        },
    };

    for task in std::mem::take(&mut config.task_blobs) {
        runtime.register_task_blob(task.blob, task.witness_addr, task.witness_capacity);
    }
    let blob_idx = runtime.register_service_blob(config.blob);
    let svc_id = runtime.register_service_with_id(blob_idx, id);

    for (key, value) in &config.storage {
        runtime.storage.write(svc_id, key, value);
    }

    // Restore state or rebuild from the DAG.
    if let Some(state_bytes) = strategy.restore() {
        runtime
            .storage
            .write(svc_id, crate::lifecycle::STATE_KEY_BYTES, &state_bytes);
        // Rehydrate the rest of the agent's keyspace — the non-STATE
        // rows previous deltas persisted.
        match strategy.restore_writes() {
            Ok(rows) => {
                for (key, value) in rows {
                    runtime.storage.write(svc_id, &key, &value);
                }
            }
            Err(e) => warn!(%id, error = %e, "agent: restoring non-state rows failed"),
        }
        info!(%id, bytes = state_bytes.len(), "agent: restored state");
    } else if recording_enabled {
        // Cold-start replay: pull every log out of the DAG and
        // feed it through `begin_replay` / `finish_replay`. Same
        // helper we use for mid-flight soft restarts.
        match strategy.replay_logs() {
            Ok(logs) if !logs.is_empty() => {
                info!(%id, dag_nodes = logs.len(), "agent: rebuilding state from DAG");
                if let Err(err) = replay_dag_into_runtime(&mut runtime, svc_id, strategy.as_ref()) {
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
                let _ = logs;
                // Materialize the state AND the rebuilt keyspace into
                // the strategy so subsequent cold starts hit the fast
                // path — restore_writes must return what replay just
                // produced, not whatever earlier deltas persisted. This
                // slate was seeded with every config.storage row (not
                // just INIT_KEY), so exclude them all.
                let state = runtime
                    .storage
                    .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
                    .map(|v| v.to_vec())
                    .unwrap_or_default();
                let host_seeded: Vec<&[u8]> = config
                    .storage
                    .iter()
                    .map(|(key, _)| key.as_slice())
                    .collect();
                if !state.is_empty()
                    && let Err(e) = strategy
                        .commit_rebuilt(&state, &rebuilt_rows(&runtime, svc_id, &host_seeded))
                {
                    let err = format!("post-replay commit failed: {e}");
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
            }
            Ok(_) => {}
            Err(e) => {
                let err = format!("replay_logs failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: runtime.panics,
                    error: Some(err),
                };
            }
        }
    }

    // Queue initial payloads. When no init payloads are supplied we
    // still kick the actor with an empty envelope so `on_start`
    // fires — matches the pre-refactor behaviour. On a Raft
    // follower the commit_with_log triggered by on_start will
    // return NotLeader, and the inbox-loop's commit-fail handler
    // soft-restarts the runtime to bring it back in sync.
    let mut pending: VecDeque<Vec<u8>> = config.init_payloads.into_iter().collect();
    if pending.is_empty() {
        pending.push_back(Vec::new());
    }

    let mut fatal_error: Option<String> = None;

    // Periodic `tick()` (when the agent declared `tick_ms`). The thread
    // synthesizes a `tick` message about every interval, between inbound
    // work — the same heartbeat the `.so` extension gets. Re-armed from
    // *now* after each fire so a slow tick doesn't build up a burst.
    let tick_interval = config.tick_ms.map(Duration::from_millis);
    let mut tick_deadline = tick_interval.map(|iv| Instant::now() + iv);

    // Loop until the node tells us to stop (or our channels
    // disconnect, which happens during collect()). No per-agent
    // idle heuristic — the node is the source of truth for "are
    // we done."
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Priority 1 — drain pending invoke requests. The caller's
        // PVM is suspended at the ecall waiting for a reply, so
        // these jump to the front of the queue.
        let mut serviced_invoke = false;
        loop {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    serviced_invoke = true;
                    bump();
                    // Set the chain to the caller's chain plus our
                    // own ID, so any outgoing invokes during this
                    // dispatch see the full lineage.
                    {
                        let mut chain = current_chain.lock().unwrap();
                        chain.clear();
                        chain.extend_from_slice(&req.chain);
                        chain.push(id.0);
                    }
                    // Stamp this thread's relay caller for the duration of the
                    // dispatch, so an outbound ask during it can relay the real
                    // caller bounded by `intra_caps` (read in `external_invoke`).
                    // Only cap-bearing agents need this propagated carrier;
                    // without a matching cap the outbound target receives no
                    // authority. Cleared on scope exit (even on panic), so a
                    // refused call cannot poison the next dispatch.
                    let _relay = (!config.intra_caps.is_empty()).then(|| {
                        RelayCallerGuard::stamp(PropagatedCaller {
                            caller: req.caller.clone(),
                            space_role: req.space_role,
                        })
                    });
                    let outcome = handle_invoke_request(
                        &mut runtime,
                        svc_id,
                        &outbox,
                        id,
                        req,
                        strategy.as_mut(),
                        recording_enabled,
                    );
                    if let Err(e) = outcome {
                        fatal_error = Some(format!("commit failed during invoke: {e}"));
                        break;
                    }
                    #[cfg(all(feature = "network", feature = "storage"))]
                    publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if fatal_error.is_some() {
            break;
        }
        if serviced_invoke {
            continue;
        }

        // Cycle 4 — drain CRDT sync notifications. The per-replica
        // ticker pings us after merging remote DAG nodes; we run
        // a soft restart to reload the strategy and replay the
        // merged log set so our in-memory state matches.
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(rx) = &sync_rx {
            let mut got_signal = false;
            while let Ok(()) = rx.try_recv() {
                got_signal = true;
            }
            // The notifier fires for every committed index, including the echo
            // of this agent's own proposals. Only reload when the backing store
            // actually gained nodes we haven't folded in (`needs_sync_reload`) —
            // soft-restarting on our own commits replays the whole DAG every
            // commit (O(n²), stalling a continuously-committing actor) and
            // transiently wipes state to genesis mid-replay.
            if got_signal && strategy.needs_sync_reload() {
                bump();
                info!(%id, "agent: CRDT sync merged new nodes; soft-restarting");
                if let Err(err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                    fatal_error = Some(format!("soft restart failed: {err}"));
                    break;
                }
                // Restart the loop so we re-check invokes that
                // may have arrived during the soft restart.
                continue;
            }
        }

        let msg = if let Some(m) = pending.pop_front() {
            bump();
            // Fresh inbox-style dispatch; chain starts at us.
            *current_chain.lock().unwrap() = vec![id.0];
            m
        } else if runtime.has_work() {
            bump();
            // Residual work — pending self-messages or transfers
            // queued by the previous dispatch. A merely suspended
            // service (continuation saved, no pending message)
            // no longer counts as residual: under the dumb-host
            // model it sleeps until a parent agent invokes it
            // again. Including `is_suspended` here would busy-spin
            // on yielded children.
            // Keep the chain set by the dispatch that produced it.
            if let Err(e) = dispatch_once(
                &mut runtime,
                svc_id,
                &outbox,
                id,
                None,
                strategy.as_mut(),
                recording_enabled,
            ) {
                // On a Raft follower the commit can return
                // NotLeader. Log, soft-restart to bring the runtime
                // back in sync, continue. CRDT failures are still
                // unexpected but the same recovery applies.
                warn!(%id, error = %e, "residual-work commit failed; soft-restarting");
                #[cfg(all(feature = "network", feature = "storage"))]
                if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut())
                {
                    fatal_error = Some(format!("residual soft restart: {restart_err}"));
                    break;
                }
                continue;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
            continue;
        } else {
            // A due periodic tick takes priority over blocking — synthesize
            // a `tick` message and dispatch it through the normal path. No
            // inbound caller, so RELAY_CALLER stays unset (a tick's outbound
            // asks relay as Unauthenticated, matching the extension tick).
            let now = Instant::now();
            if let Some(deadline) = tick_deadline
                && now >= deadline
            {
                bump();
                *current_chain.lock().unwrap() = vec![id.0];
                tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
                encode_tick_payload()
            } else {
                // Short blocking wait on inbox so we re-check the shutdown
                // flag and the invoke channel promptly, waking by the tick
                // deadline so ticks stay roughly on cadence.
                let wait = match tick_deadline {
                    Some(deadline) => deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(50)),
                    None => Duration::from_millis(50),
                };
                match inbox.recv_timeout(wait) {
                    Ok(env) => {
                        bump();
                        *current_chain.lock().unwrap() = vec![id.0];
                        env.payload
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        };
        if let Err(e) = dispatch_once(
            &mut runtime,
            svc_id,
            &outbox,
            id,
            Some(msg),
            strategy.as_mut(),
            recording_enabled,
        ) {
            // Tell-style dispatch on a follower will return
            // NotLeader. Soft-restart and continue rather than
            // killing the agent; the message is effectively
            // dropped (which is OK — clients should target the
            // leader).
            warn!(%id, error = %e, "tell-style commit failed; soft-restarting");
            #[cfg(all(feature = "network", feature = "storage"))]
            if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                fatal_error = Some(format!("soft restart: {restart_err}"));
                break;
            }
            continue;
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
    }

    if let Some(err) = &fatal_error {
        error!(%id, "{err}");
    }
    AgentResult {
        id,
        panics: runtime.panics,
        error: fatal_error,
    }
}

/// Publish the strategy's current roots on the gossipsub topic
/// for `rep_id` if the agent is replicated and a network is
/// attached. Cheap when not replicated (early return); the
/// strategy's `roots()` is also a no-op for non-CRDT types.
#[cfg(all(feature = "network", feature = "storage"))]
fn publish_heads_if_replicated(
    shared_network: &SharedNetwork,
    rep_id: Option<[u8; 32]>,
    strategy: &dyn crate::commit::CommitStrategy,
) {
    let Some(rep_id) = rep_id else {
        return;
    };
    let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    let roots = strategy.roots();
    if roots.is_empty() {
        return;
    }
    net.publish_heads(rep_id, roots);
}

/// Handle a synchronous invoke request from a peer: dispatch the
/// message through this agent's runtime, capture the reply bytes
/// (rkyv-encoded `Value`), and send them back through the caller's
/// reply channel. The CALLER's `handle_invoke` wraps the reply in
/// the invoke wire frame (`[STATUS_DONE][state_len=0][reply]`) —
/// same convention workers use, so this path is symmetric with
/// `extension_thread`.
///
/// Recording is honored: a CRDT-mode agent records the dispatch
/// just like any other external message, since from its own
/// perspective the invoke IS its external event for that tick.
fn handle_invoke_request(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    req: InvokeRequest,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
) -> Result<(), crate::commit::CommitError> {
    let dispatch_caller_prefix = caller_prefix_bytes(&req);
    let invocation_id = next_dispatch_invocation_id(strategy, svc_id);
    if recording_enabled {
        runtime.begin_recording(req.msg.clone());
    }
    // Wrap the dispatch payload with a caller-info header so the PVM
    // agent can populate Context::caller and role bytes from the caller info.
    // Format: see lifecycle::TAG_DISPATCH_PREFIX.
    let payload = encode_caller_prefix(&req, invocation_id);
    send_if_deliverable(runtime, svc_id, payload);

    // Drive to quiescence, buffering external transfers as we go. The
    // runtime discards transfers to services it doesn't host on the tick
    // that would deliver them, so draining after each tick is the only
    // way to capture them. They are routed only after the commit below
    // succeeds: routing before commit leaked messages when the commit
    // failed (e.g. Raft `NotLeader` because we lost leadership between
    // dispatch and commit) — the caller retries against the new leader,
    // which routes them there, so an early send would duplicate, and if
    // the retry never comes, orphan them.
    let external = drive_capturing_external(runtime, svc_id);

    // A producer-private proof-record request under CRDT/Raft rejects the
    // entire dispatch. The runtime has rolled back its journal; discard the
    // recording too because its incoming message may itself contain the
    // witness. Committing even an otherwise-empty log would disclose it to
    // replicas.
    if recording_enabled && runtime.private_record_rejected() {
        let _ = runtime.take_dispatch_delta(svc_id);
        let _ = runtime.take_dispatch_anchor(svc_id);
        let _ = runtime.finish_recording().expect("recording was started");
        let _ = runtime.take_last_reply(svc_id);
        let _ = runtime.take_last_status(svc_id);
        drop(external);
        drop(req.reply);
        return Ok(());
    }

    // Persist before replying. If the commit fails, we drop the reply so
    // the caller sees `Unreachable` and can retry against the new leader.
    // Doing it in this order means the client only sees success when the
    // state is durable.
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    // The whole-agent delta this dispatch produced: its ordered writes
    // (STATE_KEY included), the anchor of the state it ran against
    // (recorded normatively in the log node — replay divergence
    // detection compares against it), and the effect-bearing marker
    // driving the durable-node rule. Taken even when not recording so
    // stale entries never leak into the next dispatch.
    let (writes, effect_bearing) = runtime.take_dispatch_delta(svc_id);
    let dispatch_anchor = runtime.take_dispatch_anchor(svc_id);
    let anchor = dispatch_anchor.unwrap_or((crate::effect_log::ANCHOR_UNRECORDED, [0u8; 32]));
    let commit_result = if recording_enabled {
        let mut log = runtime.finish_recording().expect("recording was started");
        log.set_anchor(anchor.0, anchor.1);
        log.set_caller_prefix(dispatch_caller_prefix);
        log.set_invocation_id(invocation_id);
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: Some(&log),
            effect_bearing,
        })
    } else {
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: None,
            effect_bearing,
        })
    };

    if let Err(e) = commit_result {
        // Drop the reply (caller surfaces `Unreachable`) and the buffered
        // transfers (nothing durable produced them), then soft-restart to
        // bring the runtime back in sync with the durable log. Don't
        // bubble the error — a transient `NotLeader` shouldn't kill the
        // agent thread.
        warn!(%svc_id, error = %e, "commit failed; soft-restarting, dropping reply and transfers");
        drop(req.reply);
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Err(restart_err) = soft_restart_crdt(runtime, svc_id, strategy) {
            error!(%svc_id, "soft restart after commit failure: {restart_err}");
        }
        return Ok(());
    }

    // Commit succeeded: the state is durable, so route the buffered
    // external transfers now.
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
            authenticated_source_peer: None,
            destination_peer: None,
        });
    }

    // Pack the reply as the full invoke wire
    // envelope `[status][state_len:u32][state][reply]` so the
    // caller's PVM sees the same shape it would for a local
    // INVOKE. `is_suspended` after `run_blocking` tells us the
    // handler yielded with a continuation still alive — STATUS_YIELDED
    // surfaces upstream so a parent agent can keep driving us tick
    // by tick. Without this distinction every cross-thread invoke
    // looks like STATUS_DONE and the caller drops yielded children
    // from its run queue.
    //
    // `take_last_reply` returns `None` only when the handler
    // panicked; we signal that to the caller by dropping
    // `reply_tx`, which surfaces upstream as `InvokeError::Panicked`.
    let reply = match runtime.take_last_reply(svc_id) {
        Some(bytes) => bytes,
        None => {
            drop(req.reply);
            return Ok(());
        }
    };
    // When the role check refused the call,
    // the runtime stashes STATUS_FORBIDDEN in last_status. That
    // wins over the default DONE/YIELDED inference so the wire
    // envelope carries the actor-level refusal end-to-end.
    let actor_status = runtime.take_last_status(svc_id);
    let status = if let Some(s) = actor_status {
        s
    } else if runtime.is_suspended(svc_id) {
        crate::actors::run::STATUS_YIELDED
    } else {
        crate::actors::run::STATUS_DONE
    };
    let envelope = encode_invoke_envelope(status, &state, &reply);
    send_reply_capped(req.reply, envelope, svc_id);
    Ok(())
}

/// Wire-byte for "no grant exists" in the registry's
/// `peer_role` probe replies. Mirrors `space_registry::AUTH_ROLE_NONE`; kept here so the host
/// doesn't need a cross-crate dep on the actor just to read a
/// single byte.
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_NONE: u8 = 0;

/// Wire-byte for the space-level ADMIN grant (the highest role). Mirrors
/// `space_registry::AUTH_ROLE_ADMIN`; used by the `__stop` lifecycle gate
/// — only an admin may stop an agent host-side.
pub(crate) const AUTH_ROLE_ADMIN: u8 = 3;

/// Wire-byte for the lowest grant tier (read / Member). Mirrors
/// `space_registry::AUTH_ROLE_READONLY`; the floor that authorizes a
/// peer to be served a private replica's sync data.
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_READONLY: u8 = 1;

/// `node_role` reply byte for an enrolled Raft VOTER: the registry's
/// `NODE_ROLE_VOTER` (0) encoded as `role + 1`. Kept as a local literal
/// — `space-registry` is only a dev-dependency of `vos`, so the const
/// can't be imported into host code; it must track
/// `space_registry::{node_role encoding, NODE_ROLE_VOTER}`.
#[cfg(feature = "network")]
pub(crate) const NODE_ROLE_REPLY_VOTER: u8 = 1;

/// The bare (un-role-gated) READ handlers on the private `msg-*` channel
/// replicas — `msg-log` (`history` / `stats`), `msg-ctl` (`commits` /
/// `commit_at` / `head`), `msg-directory` (`kp_count` / `channels`).
/// dispatch gate ([`NodeService::dispatch_invoke`]) membership-checks REMOTE
/// invokes of these: they expose ciphertext / channel metadata the sync path
/// already gates. The actors' WRITE handlers carry `#[msg(role = …)]` and are
/// intentionally ABSENT here — they're left to the actor's own gate so raft
/// leader-forward works. Must track the read surface of those three crates.
#[cfg(feature = "network")]
fn is_private_read_method(method: &str) -> bool {
    matches!(
        method,
        "history" | "stats" | "commits" | "commit_at" | "head" | "kp_count" | "channels"
    )
}

/// Build a failure envelope the libp2p layer relays back to
/// the caller when the dispatch-layer auth gate refuses a call.
/// `STATUS_FORBIDDEN` is the distinct status the client-side
/// `Invoker for &VosNode` peeks at (see `vos/src/lib.rs`) so
/// vosx surfaces "permission denied" rather than colliding with
/// a generic actor panic.
///
/// Host-side fallback (e.g. for a future
/// quota / rate-limit gate); the actor-level role check now
/// produces STATUS_FORBIDDEN through the agent's own dispatch.
///
/// Shape: exactly 5 bytes — `[STATUS_FORBIDDEN, 0, 0, 0, 0]`
/// (status + zero-length state). Both the length and the leading
/// status byte are load-bearing for the client-side detection.
#[cfg(feature = "network")]
#[allow(dead_code)]// Retained as host-side fallback; see doc comment above.
fn forbidden_envelope() -> Vec<u8> {
    use crate::actors::run::STATUS_FORBIDDEN;
    encode_invoke_envelope(STATUS_FORBIDDEN, &[], &[])
}

/// Replay-side wrapper for already-logged messages. Always
/// emits a trusted-System prefix so the role
/// check passes during replay — original authorisation is
/// implicit in the fact the log was committed.
fn encode_replay_payload(
    prefix: &crate::effect_log::CallerPrefix,
    invocation_id: crate::service::InvocationId,
    msg: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(38 + msg.len());
    out.push(crate::actors::lifecycle::TAG_DISPATCH_PREFIX);
    out.extend_from_slice(prefix);
    out.extend_from_slice(invocation_id.as_bytes());
    out.extend_from_slice(msg);
    out
}

/// Wrap an inbox-sourced payload with the safe default caller
/// prefix (Caller::Unauthenticated, no role bytes). Closes the
/// forged-caller-prefix attack on Tells — see the SECURITY
/// comment in `dispatch_once`. Inbox payloads have no
/// trustworthy origin (external libp2p Tells set
/// attacker-controlled `from` fields), so the wrap *always*
/// uses Unauthenticated regardless of `env.from`.
fn wrap_with_unauthenticated_prefix(
    msg: &[u8],
    invocation_id: crate::service::InvocationId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(38 + msg.len());
    out.push(crate::actors::lifecycle::TAG_DISPATCH_PREFIX);
    out.push(0); // trust_flag = external (Unauthenticated)
    out.push(0); // has_space_role
    out.push(0); // space byte (unused)
    out.push(0); // has_actor_local_role
    out.push(0); // actor_local byte (unused)
    out.extend_from_slice(invocation_id.as_bytes());
    out.extend_from_slice(msg);
    out
}

/// Enqueue `payload` for `svc_id` only if the guest can actually fetch it.
///
/// The actor's dispatch loop reads each queued item into a fixed `BUF_SIZE`
/// buffer (`lifecycle::fetch_raw`), so an item larger than that is
/// undeliverable: `fetch_raw` reports truncation (`n > buf.len()`) and the loop
/// treats it as end-of-queue, dropping the oversize item AND skipping anything
/// queued behind it in the same round. Enqueuing such an item is never useful,
/// so refuse it LOUDLY here rather than silently poisoning the queue. `payload`
/// is the already-wrapped dispatch item (caller-prefix header included), so the
/// effective message ceiling is `BUF_SIZE` minus that header.
///
/// This guard lives in the VOS dispatch layer, not `VosRuntime::send_to`, so
/// the PVM/service platform-aligned runtime and the `FETCH` hostcall stay buffer-size-
/// agnostic (a guest with a larger buffer would accept a larger item). Returns
/// `true` when the item fit and was enqueued.
fn send_if_deliverable(runtime: &mut VosRuntime, svc_id: ServiceId, payload: Vec<u8>) -> bool {
    use crate::actors::lifecycle::BUF_SIZE;
    if payload.len() > BUF_SIZE {
        tracing::warn!(
            service = svc_id.0,
            payload_len = payload.len(),
            buf_size = BUF_SIZE,
            "refusing undeliverable dispatch: wrapped payload exceeds the guest FETCH buffer \
             (BUF_SIZE); the actor cannot receive it — reduce the message size",
        );
        return false;
    }
    runtime.send_to(svc_id, payload);
    true
}

/// Drive the runtime to quiescence, buffering the external transfers each
/// tick produces before the next tick would discard them. The runtime
/// drops transfers addressed to services it doesn't host on the tick that
/// tries to deliver them, so a plain `run_blocking()` followed by one
/// `drain_external_transfers` loses any transfer bound for another agent;
/// draining after each tick captures them for the node to route.
fn drive_capturing_external(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
) -> Vec<(ServiceId, Vec<u8>)> {
    let mut external = Vec::new();
    while runtime.has_work() {
        runtime.tick_blocking();
        external.extend(runtime.drain_external_transfers(svc_id));
    }
    external
}

/// Wrap the request's message bytes with a caller-info header so the
/// PVM agent can populate `Context::caller` and the role bytes from caller info.
///
/// Layout (38 bytes header + original message):
///
///   [0] TAG_DISPATCH_PREFIX (0xFD)
///   [1] internal_origin: 1 iff caller is System/Actor (intra-process)
///   [2] has_space_role: 0 / 1
///   [3] space_role byte
///   [4] has_actor_local_role: 0 / 1
///   [5] actor_local_role byte
///   [6..38] stable InvocationId
///   [38..] original message bytes
fn encode_caller_prefix(
    req: &InvokeRequest,
    invocation_id: crate::service::InvocationId,
) -> Vec<u8> {
    let prefix = caller_prefix_bytes(req);
    let mut out = Vec::with_capacity(38 + req.msg.len());
    out.push(crate::actors::lifecycle::TAG_DISPATCH_PREFIX);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(invocation_id.as_bytes());
    out.extend_from_slice(&req.msg);
    out
}

/// The 5 caller-prefix bytes of [`encode_caller_prefix`], standalone —
/// recorded in the dispatch's EffectLog so replay re-runs the dispatch
/// under the original caller's authority (a role-refused dispatch must
/// replay as refused).
fn caller_prefix_bytes(req: &InvokeRequest) -> crate::effect_log::CallerPrefix {
    let internal_origin: u8 = if matches!(
        req.caller,
        crate::actors::Caller::System | crate::actors::Caller::Actor(_)
    ) {
        1
    } else {
        0
    };
    let (has_space, space_byte) = match req.space_role {
        Some(b) => (1u8, b),
        None => (0u8, 0u8),
    };
    let (has_actor_local, actor_local_byte) = match req.actor_local_role {
        Some(b) => (1u8, b),
        None => (0u8, 0u8),
    };
    [
        internal_origin,
        has_space,
        space_byte,
        has_actor_local,
        actor_local_byte,
    ]
}

/// Allocate the identity visible to one live handler dispatch.
///
/// CRDT strategies return the exact identity of the durable event they will
/// append, which is stable across retry and reconstructible during replay.
/// Other production paths still await the service WorkEnvelope cutover, so they use
/// a process-local monotone fallback. Those histories never merge as CRDT
/// branches; the fallback exists so ordinary handlers still receive a distinct
/// typed invocation identity in this staging runtime.
fn next_dispatch_invocation_id(
    strategy: &dyn crate::commit::CommitStrategy,
    svc_id: ServiceId,
) -> crate::service::InvocationId {
    static NEXT_FALLBACK_INVOCATION: AtomicU64 = AtomicU64::new(1);

    strategy.pending_invocation_id().unwrap_or_else(|| {
        let sequence = NEXT_FALLBACK_INVOCATION.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&svc_id.0.to_le_bytes());
        nonce[4..].copy_from_slice(&sequence.to_le_bytes());
        crate::service::InvocationId::derive(b"vos/host-dispatch/service", &nonce)
    })
}

/// INVOKE. Used by the cross-thread invoke path so a yielded child on
/// another agent thread surfaces as `STATUS_YIELDED` (with its post-
/// dispatch state) to the calling actor's `lifecycle::invoke_raw`,
/// not as `STATUS_DONE`.
fn encode_invoke_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + state.len() + reply.len());
    out.push(status);
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(reply);
    out
}

/// Strip the invoke envelope back to just the rkyv-encoded reply
/// bytes for host-side callers (`VosNode::invoke`, peer invoke
/// forwarding) who don't care about YIELDED/DONE — they only want
/// the handler's return value. A short envelope or one carrying a
/// failure status (`STATUS_NOT_FOUND` / `STATUS_PANICKED` /
/// `STATUS_OOG` / `STATUS_FORBIDDEN`) decodes as `None` so the
/// worker and other ask-style callers can distinguish "actor
/// returned nothing" from "actor failed".
fn unwrap_invoke_envelope(envelope: &[u8]) -> Option<Vec<u8>> {
    unwrap_invoke_envelope_result(envelope).ok()
}

fn unwrap_invoke_envelope_result(envelope: &[u8]) -> Result<Vec<u8>, u8> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    if envelope.len() < 5 {
        return Err(envelope
            .first()
            .copied()
            .unwrap_or(crate::actors::run::STATUS_PANICKED));
    }
    match envelope[0] {
        STATUS_DONE | STATUS_YIELDED => {}
        status => return Err(status),
    }
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let reply_start = 5 + state_len;
    if reply_start > envelope.len() {
        return Err(crate::actors::run::STATUS_PANICKED);
    }
    Ok(envelope[reply_start..].to_vec())
}

fn decode_host_invoke_envelope(
    envelope: &[u8],
) -> Result<Vec<u8>, crate::actors::client::ClientError> {
    use crate::actors::client::{CallError, ClientError};
    use crate::actors::run::{
        STATUS_DONE, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED,
        STATUS_TOO_BIG, STATUS_YIELDED,
    };
    let Some(status) = envelope.first().copied() else {
        return Err(ClientError::Unreachable);
    };
    match status {
        STATUS_DONE | STATUS_YIELDED => {
            if envelope.len() < 5 {
                return Err(ClientError::Unreachable);
            }
            let state_len = u32::from_le_bytes(
                envelope[1..5]
                    .try_into()
                    .map_err(|_| ClientError::Unreachable)?,
            ) as usize;
            let reply_start = 5_usize
                .checked_add(state_len)
                .filter(|offset| *offset <= envelope.len())
                .ok_or(ClientError::Unreachable)?;
            Ok(envelope[reply_start..].to_vec())
        }
        STATUS_FORBIDDEN => Err(ClientError::Forbidden),
        STATUS_NOT_FOUND => Err(ClientError::NotFound),
        STATUS_PANICKED => Err(ClientError::Call(CallError::Panicked)),
        STATUS_OOG => Err(ClientError::Call(CallError::OutOfGas)),
        STATUS_TOO_BIG => Err(ClientError::Call(CallError::ReplyTooBig)),
        other => Err(ClientError::Call(CallError::Unknown(other))),
    }
}

/// Decode a cross-thread invoke envelope back into the
/// [`runtime::ExternalInvokeReply`] enum the runtime's
/// `external_invoke` callback expects, so a yielded child on one
/// agent thread surfaces as [`runtime::ExternalInvokeReply::Yielded`]
/// to the calling actor's PVM.
///
/// A short envelope (just a status byte — `STATUS_NOT_FOUND` /
/// `STATUS_PANICKED`) returns `None`; the runtime then falls
/// through to its own NOT_FOUND path.
fn decode_invoke_envelope(envelope: &[u8]) -> Option<crate::runtime::ExternalInvokeReply> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    use crate::runtime::ExternalInvokeReply;
    if envelope.len() < 5 {
        return None;
    }
    let status = envelope[0];
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let state_end = 5 + state_len;
    if state_end > envelope.len() {
        return None;
    }
    let state = envelope[5..state_end].to_vec();
    let reply = envelope[state_end..].to_vec();
    match status {
        STATUS_YIELDED => Some(ExternalInvokeReply::Yielded { state, reply }),
        STATUS_DONE => Some(ExternalInvokeReply::Done(reply)),
        _ => None,
    }
}

/// Run one dispatch cycle: optionally begin recording, deliver the
/// message (or just drive residual work), route external transfers,
/// then commit the resulting state via the strategy.
///
/// Returns `Err` only on host-side commit failures — those are
/// terminal for the agent. Routing failures and transient runtime
/// issues are not surfaced here.
fn dispatch_once(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    msg: Option<Vec<u8>>,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
) -> Result<(), crate::commit::CommitError> {
    let invocation_id = next_dispatch_invocation_id(strategy, svc_id);
    let recorded = recording_enabled
        && if let Some(payload) = msg.as_ref() {
            runtime.begin_recording(payload.clone());
            true
        } else {
            false
        };
    if let Some(payload) = msg {
        // SECURITY: wrap with Caller::Unauthenticated *before*
        // dispatching so the actor's dispatch_one always sees
        // a host-controlled caller prefix. Without this wrap, an
        // attacker could send a libp2p Tell whose payload begins
        // with TAG_CALLER_PREFIX (0xFE) and have dispatch_one
        // strip + parse the attacker's bytes as a "host-issued"
        // caller assertion — forging trust=System bypasses every
        // role check. With the wrap, the attacker's prefix bytes
        // become inner-message bytes the Msg decoder mis-parses
        // and rejects.
        //
        // Internal Tells (ctx.tell from one actor to another)
        // could legitimately want Caller::Actor trust, but the
        // inbox mixes them with external Tells and `env.from` is
        // attacker-controlled in the external case — so the safe
        // default is Unauthenticated for everything that arrives
        // through this path. Intra-system callers that need
        // trusted dispatch use ctx.ask (invoke path), which goes
        // through handle_invoke_request and gets the right
        // Caller::Actor wrap.
        //
        // Empty payloads are the runtime's wake-up tick (used to
        // re-schedule yielded services); the runtime filters them
        // out before dispatch and they never reach dispatch_one
        // (see `runtime.rs::run_blocking`'s round_items retain).
        // Wrapping would turn them into non-empty bytes that
        // *aren't* filtered, then trip the empty-Msg decoder.
        // Skip the wrap; empty in / empty out preserves the
        // wake-up semantics.
        let payload = if payload.is_empty() {
            payload
        } else {
            wrap_with_unauthenticated_prefix(&payload, invocation_id)
        };
        send_if_deliverable(runtime, svc_id, payload);
    }

    // Drive to quiescence, buffering external transfers each tick before
    // the next tick discards them; route them only after the commit
    // succeeds so a failed commit (e.g. Raft `NotLeader`) leaks nothing.
    let external = drive_capturing_external(runtime, svc_id);

    // See `handle_invoke_request`: the secret may be present in the incoming
    // message even though the runtime emitted no ProofRecordEntry, so no log
    // from this rejected dispatch may reach the commit strategy.
    if recorded && runtime.private_record_rejected() {
        let _ = runtime.take_dispatch_delta(svc_id);
        let _ = runtime.take_dispatch_anchor(svc_id);
        let _ = runtime.finish_recording().expect("recording was started");
        let _ = runtime.take_last_reply(svc_id);
        let _ = runtime.take_last_status(svc_id);
        drop(external);
        return Ok(());
    }

    // See handle_invoke_request — the dispatch's whole-agent delta,
    // taken unconditionally so stale entries never leak across
    // dispatches.
    let (writes, effect_bearing) = runtime.take_dispatch_delta(svc_id);
    let dispatch_anchor = runtime.take_dispatch_anchor(svc_id);
    let anchor = dispatch_anchor.unwrap_or((crate::effect_log::ANCHOR_UNRECORDED, [0u8; 32]));
    if recorded {
        let mut log = runtime.finish_recording().expect("recording was started");
        log.set_anchor(anchor.0, anchor.1);
        // Tell-style dispatches were wrapped Unauthenticated; kicks
        // (empty msg) carry no prefix and replay as raw empties, so the
        // recorded prefix is unused for them.
        log.set_caller_prefix([0, 0, 0, 0, 0]);
        log.set_invocation_id(invocation_id);
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: Some(&log),
            effect_bearing,
        })?;
    } else {
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: None,
            effect_bearing,
        })?;
    }

    // Commit succeeded (the `?` above returns early on failure): the
    // state is durable, so route the buffered transfers now.
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
            authenticated_source_peer: None,
            destination_peer: None,
        });
    }
    Ok(())
}

/// Select the agent's commit strategy from its config.
///
/// Returns `Err` when a non-`Ephemeral` strategy was requested but
/// the underlying redb open failed, or when storage was requested
/// without a `data_dir`. We deliberately do not silently downgrade
/// to `NoCommit` — a CRDT actor that can't open its DAG file
/// shouldn't pretend to be replicated.
/// Derive the per-replica `CrdtEvent.origin` from the group's
/// replication_id and the host node's 16-bit prefix.
///
/// `blake2b("vos-replica-origin" || replication_id || prefix)`
/// — the prefix domain-separates replicas of the same group
/// running on different nodes, while the replication_id
/// domain-separates groups that happen to share a node. The
/// prefix string keeps this hash from colliding with other vos
/// blake2b uses (registry rep_id derivation, etc).
#[cfg(feature = "storage")]
fn derive_replica_origin(replication_id: &[u8; 32], node_prefix: u16) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-replica-origin");
    h.update(&[0u8]);
    h.update(replication_id);
    h.update(&node_prefix.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn build_agent_strategy(
    config: &AgentConfig,
    id: ServiceId,
    self_node_prefix: u16,
) -> Result<Box<dyn crate::commit::CommitStrategy>, crate::commit::CommitError> {
    #[cfg(feature = "storage")]
    {
        let _ = (id, self_node_prefix);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            Consistency::Local => {
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Local consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::LocalCommit::open(&path)?))
            }
            Consistency::Crdt => {
                // CRDT events are tagged with a per-replica origin
                // so peer replicas can tell our events apart from
                // theirs by content alone. Two replicas of the same
                // group share the *replication_id* (it's the group
                // identity for sync/discovery), so we can't reuse
                // that — the per-replica origin is derived from
                // `(replication_id, node_prefix)` so:
                //   - replicas on different nodes get different
                //     origins (different prefixes),
                //   - a replica's origin is stable across restarts
                //     of the same node (same prefix),
                //   - origins are domain-separated by group, so
                //     two unrelated groups on the same node never
                //     share origins.
                // We still require `replication_id` to be set
                // explicitly: an unconfigured Crdt agent has no
                // group identity to sync against, which is a
                // silent determinism failure waiting to happen.
                let replication_id = config.replication_id.ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires AgentConfig::replication_id; \
                         set one explicitly or use `auto_replication_id(name)`"
                            .into(),
                    )
                })?;
                let replica_origin = derive_replica_origin(&replication_id, self_node_prefix);
                if let Some(arc) = &config.pre_opened_db {
                    let mut cc = match &config.pre_opened_lock {
                        Some(lock) => crate::commit::CrdtCommit::from_db_arc_locked(
                            arc.clone(),
                            lock.clone(),
                            replica_origin,
                        ),
                        None => crate::commit::CrdtCommit::from_db_arc(arc.clone(), replica_origin),
                    }?;
                    cc.set_node_validator(config.node_validator.clone());
                    return Ok(Box::new(cc));
                }
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                let mut cc = crate::commit::CrdtCommit::open(&path, replica_origin)?;
                cc.set_node_validator(config.node_validator.clone());
                Ok(Box::new(cc))
            }
            Consistency::Raft => {
                // Single-node-only path: agent_thread handles the
                // multi-mode case before reaching here (it owns
                // the pre-spawned worker via `config.raft_worker`).
                let cfg = crate::raft::RaftConfig {
                    me: self_node_prefix,
                    members: config.members.clone(),
                    replication_id: config.replication_id.unwrap_or([0u8; 32]),
                    ..crate::raft::RaftConfig::default()
                };
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Raft consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::raft::RaftCommit::open(&path, cfg)?))
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id, self_node_prefix);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            other => Err(crate::commit::CommitError::Config(format!(
                "consistency={other:?} requires the `storage` feature"
            ))),
        }
    }
}

// ── Worker thread ────────────────────────────────────────────────────

fn extension_startup_failed(
    startup: &mpsc::SyncSender<Result<(), String>>,
    id: ServiceId,
    panics: u32,
    error: String,
) -> AgentResult {
    let _ = startup.send(Err(error.clone()));
    AgentResult {
        id,
        panics,
        error: Some(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn extension_thread(
    id: ServiceId,
    config: ExtensionConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    agent_names: AgentNames,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    proof_blobs: ProofBlobStore,
    proof_blobs_dir: Option<std::path::PathBuf>,
    raft_fwd: RaftFwd,
    startup: mpsc::SyncSender<Result<(), String>>,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
) -> AgentResult {
    use crate::extension::ExtensionPlugin;
    // SAFETY: ExtensionPlugin::load wraps libloading::Library; it's
    // only unsafe because dlopen runs the .so's static initialisers
    // and binds C symbols whose type signatures we can't verify at
    // compile time. We trust the operator's manifest path to point
    // at a vos-built extension.
    let plugin = match unsafe { ExtensionPlugin::load(&config.path) } {
        Ok(p) => p,
        Err(e) => {
            let err = format!("failed to load extension plugin: {e}");
            error!(%id, "extension: {err}");
            return extension_startup_failed(&startup, id, 1, err);
        }
    };

    if let Some(meta) = plugin.meta() {
        info!(%id, actor = %meta.actor_name, path = %config.path.display(), "extension: loaded plugin");
    }

    let bump = || *activity.lock().unwrap() = Instant::now();

    // Pick a persistence strategy. Extensions always get LocalCommit
    // when a data directory is configured, NoCommit otherwise;
    // replication strategies (CRDT, Raft) are not available to
    // extensions since they live outside the deterministic universe.
    let mut strategy: Box<dyn crate::commit::CommitStrategy> =
        match build_extension_strategy(&config) {
            Ok(strategy) => strategy,
            Err(error) => {
                error!(%id, %error, "extension: persistence setup failed");
                return extension_startup_failed(&startup, id, 0, error);
            }
        };
    let saved_state = match strategy.restore_checked() {
        Ok(state) => state,
        Err(error) => {
            let message = format!("extension state restore failed: {error}");
            error!(%id, %error, "extension: failed to restore persisted state");
            return extension_startup_failed(&startup, id, 0, message);
        }
    };

    let instance = match saved_state {
        Some(bytes) => {
            info!(%id, bytes = bytes.len(), "extension: restored state");
            plugin.load_state(&bytes)
        }
        None if config.init_args.is_empty() => plugin.try_create(),
        None => plugin.try_create_with_args(&config.init_args),
    };
    let mut instance = match instance {
        Ok(instance) => instance,
        Err(error) => {
            error!(%id, %error, "extension: creation or persisted state load failed");
            return extension_startup_failed(&startup, id, 0, error);
        }
    };

    // Exercise both state serialization and the configured commit backend
    // before publishing a route. This catches a bad state ABI or a database
    // that can open but cannot commit while registration is still fallible.
    if let Err(error) = persist(strategy.as_mut(), &instance) {
        let message = format!("extension initial state commit failed: {error}");
        error!(%id, %error, "extension: initial persistence check failed");
        return extension_startup_failed(&startup, id, 0, message);
    }

    if startup.send(Ok(())).is_err() {
        return AgentResult {
            id,
            panics: 0,
            error: Some("extension registration was abandoned during startup".into()),
        };
    }

    let blob_fetch = BlobFetchCtx {
        proof_blobs: &proof_blobs,
        proof_blobs_dir: proof_blobs_dir.as_deref(),
        #[cfg(feature = "network")]
        shared_network: &shared_network,
    };

    // Host-side cooperative executor. Created once on THIS thread
    // (the thread that owns the instance) and driven per-message via
    // `block_on(ex.run(..))`. The `!Send` per-task futures stay local to it.
    // Extension dispatch is N=1 (one root task to completion before the next message),
    // so no task is ever spawned on it here.
    let ex = async_executor::LocalExecutor::new();

    // Periodic `tick()`. When the manifest set `tick_ms`, the
    // driver dispatches a synthetic `tick` message to the actor's `tick`
    // handler about every interval, *between* inbound work. Best-effort cadence: a
    // long invoke delays the next tick (the driver never preempts a handler).
    // `tick_disabled` latches if the extension declares `tick_ms` but has no
    // `tick` handler (the synthetic dispatch returns `Err`), so a misconfig
    // logs once instead of re-dispatching every interval.
    let tick_interval = config.tick_ms.map(Duration::from_millis);
    let mut tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
    let mut tick_disabled = false;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Fire a due periodic tick before servicing inbound work, so a
        // backlog of invokes can't starve the heartbeat indefinitely.
        if let (Some(deadline), false) = (tick_deadline, tick_disabled) {
            if Instant::now() >= deadline {
                bump();
                let payload = encode_tick_payload();
                let task_context = crate::extension::ExtensionInvocationContext::new(
                    id,
                    next_dispatch_invocation_id(strategy.as_ref(), id),
                    crate::actors::Caller::Unauthenticated,
                    None,
                    None,
                );
                // No external caller → RELAY_CALLER unset → a tick's
                // `ctx.ask` relays as `Unauthenticated`
                // (no authenticated caller to propagate).
                let outcome = dispatch_and_poll(
                    &ex,
                    &mut instance,
                    &payload,
                    task_context,
                    id,
                    &[id.0],
                    &blob_fetch,
                    &invoke_routes,
                    &config.intra_caps,
                    &agent_names,
                    &raft_fwd,
                );
                match outcome {
                    DispatchOutcome::Ok(_) => {}
                    DispatchOutcome::NoHandler => {
                        warn!(
                            %id,
                            "extension: tick_ms set but no `tick` handler exists — disabling periodic ticks"
                        );
                        tick_disabled = true;
                    }
                    DispatchOutcome::Panicked => {
                        let message =
                            "extension tick handler panicked; refusing to retain partial state"
                                .to_owned();
                        error!(%id, "{message}");
                        return AgentResult {
                            id,
                            panics: 1,
                            error: Some(message),
                        };
                    }
                }
                if let Err(error) = persist(strategy.as_mut(), &instance) {
                    let message = format!("extension state commit failed: {error}");
                    error!(%id, %error, "extension: failed to persist tick state");
                    return AgentResult {
                        id,
                        panics: 0,
                        error: Some(message),
                    };
                }
                // Re-arm from *now* (not deadline+iv) so a slow tick doesn't
                // build up a burst of catch-up ticks.
                tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
            }
        }

        // Process up to a few invoke requests per iteration to avoid
        // starving the regular inbox.
        for _ in 0..4 {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    if req
                        .native_call
                        .as_ref()
                        .is_some_and(|control| !control.try_start())
                    {
                        // The service caller won the queued-work cancellation
                        // race (or its deadline elapsed before dequeue). The
                        // extension actor is deliberately left untouched.
                        let failure =
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[]);
                        send_reply_capped(req.reply, failure, id);
                        continue;
                    }
                    bump();
                    let task_context = crate::extension::ExtensionInvocationContext::new(
                        id,
                        req.invocation_id
                            .unwrap_or_else(|| next_dispatch_invocation_id(strategy.as_ref(), id)),
                        req.caller.clone(),
                        req.space_role,
                        req.actor_local_role,
                    );
                    let mut invoke_chain = req.chain.clone();
                    invoke_chain.push(id.0);
                    // Stamp the real caller of this invoke for
                    // the duration of the dispatch. The task context exposes it
                    // to the handler, while `RELAY_CALLER` propagates it through
                    // an `EFFECT_ASK` (bounded by `intra_caps`) instead of the
                    // `Caller::Actor` bypass. RAII-cleared after the dispatch
                    // (and on panic, via the catch in run_ext_task) so it never
                    // leaks to the next invoke or a self-originated call. The
                    // envelope path below leaves it unstamped and unauthenticated.
                    let outcome = {
                        let _relay = RelayCallerGuard::stamp(PropagatedCaller {
                            caller: req.caller.clone(),
                            space_role: req.space_role,
                        });
                        dispatch_and_poll(
                            &ex,
                            &mut instance,
                            &req.msg,
                            task_context,
                            id,
                            &invoke_chain,
                            &blob_fetch,
                            &invoke_routes,
                            &config.intra_caps,
                            &agent_names,
                            &raft_fwd,
                        )
                    };
                    // Workers don't yield — pack as DONE with no
                    // state so the caller's invoke_raw decodes
                    // `InvokeResult::Done { state: empty, reply }`.
                    // A missing handler becomes STATUS_PANICKED so ingress
                    // response decoding can distinguish it from a legitimate
                    // `()` return. A true handler panic takes the fatal path
                    // below and deliberately skips persistence.
                    if matches!(&outcome, DispatchOutcome::Panicked) {
                        let failure =
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[]);
                        send_reply_capped(req.reply, failure, id);
                        let message =
                            "extension invoke handler panicked; refusing to retain partial state"
                                .to_owned();
                        error!(%id, "{message}");
                        return AgentResult {
                            id,
                            panics: 1,
                            error: Some(message),
                        };
                    }
                    let envelope = match outcome {
                        DispatchOutcome::Ok(reply) => {
                            encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply)
                        }
                        DispatchOutcome::NoHandler => {
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[])
                        }
                        DispatchOutcome::Panicked => unreachable!("handled above"),
                    };
                    // Commit before exposing the handler result. A caller must
                    // never receive a signing capability or other stateful
                    // success whose actor state is not yet durable.
                    if let Err(error) = persist(strategy.as_mut(), &instance) {
                        let message = format!("extension state commit failed: {error}");
                        error!(%id, %error, "extension: failed to persist invoke state");
                        let failure =
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[]);
                        send_reply_capped(req.reply, failure, id);
                        return AgentResult {
                            id,
                            panics: 0,
                            error: Some(message),
                        };
                    }
                    send_reply_capped(req.reply, envelope, id);
                }
                Err(_) => break,
            }
        }

        // Cap the inbox wait at the time remaining until the next tick so the
        // heartbeat cadence holds even with an otherwise-idle inbox; floor at
        // the regular 50ms poll otherwise.
        let recv_timeout = match tick_deadline {
            Some(deadline) if !tick_disabled => deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
            _ => Duration::from_millis(50),
        };
        let envelope = match inbox.recv_timeout(recv_timeout) {
            Ok(e) => {
                bump();
                e
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        // Envelope path: actor-to-actor messaging carries no external caller,
        // so `RELAY_CALLER` stays unset → any `ctx.ask` here relays as
        // `Unauthenticated` (no authenticated caller to propagate).
        let task_context = crate::extension::ExtensionInvocationContext::new(
            id,
            next_dispatch_invocation_id(strategy.as_ref(), id),
            crate::actors::Caller::Unauthenticated,
            None,
            None,
        );
        let outcome = dispatch_and_poll(
            &ex,
            &mut instance,
            &envelope.payload,
            task_context,
            id,
            &[id.0],
            &blob_fetch,
            &invoke_routes,
            &config.intra_caps,
            &agent_names,
            &raft_fwd,
        );
        // Envelope-mode replies don't carry the `[status][state][reply]`
        // wrapper — that's an invoke-channel detail. On the envelope
        // path the receiver just gets the reply bytes addressed
        // `from = target`. A missing handler becomes an empty reply. A true
        // panic sends the same empty failure shape, then terminates without
        // persisting partial state. Always reply so an ask-style caller does
        // not hang for the full reply timeout.
        if matches!(&outcome, DispatchOutcome::Panicked) {
            let _ = outbox.send(Envelope {
                from: id,
                to: envelope.from,
                payload: Vec::new(),
                authenticated_source_peer: None,
                destination_peer: None,
            });
            let message =
                "extension envelope handler panicked; refusing to retain partial state".to_owned();
            error!(%id, "{message}");
            return AgentResult {
                id,
                panics: 1,
                error: Some(message),
            };
        }
        let reply_bytes = match outcome {
            DispatchOutcome::Ok(b) => b,
            DispatchOutcome::NoHandler => Vec::new(),
            DispatchOutcome::Panicked => unreachable!("handled above"),
        };
        if let Err(error) = persist(strategy.as_mut(), &instance) {
            let message = format!("extension state commit failed: {error}");
            error!(%id, %error, "extension: failed to persist envelope state");
            let _ = outbox.send(Envelope {
                from: id,
                to: envelope.from,
                payload: Vec::new(),
                authenticated_source_peer: None,
                destination_peer: None,
            });
            return AgentResult {
                id,
                panics: 0,
                error: Some(message),
            };
        }
        let _ = outbox.send(Envelope {
            from: id,
            to: envelope.from,
            payload: reply_bytes,
            authenticated_source_peer: None,
            destination_peer: None,
        });
    }

    AgentResult {
        id,
        panics: 0,
        error: None,
    }
}

/// Caller context an extension relays on an outbound call: the
/// identity that invoked the extension's handler plus its space-wide
/// role byte. Propagated so the extension acts as a transparent
/// relay — the downstream actor sees who really called, not the
/// extension's own id.
///
/// `actor_local_role` is intentionally dropped: the incoming byte was
/// computed for the *extension* as target and is meaningless for a
/// downstream actor; this path does not re-look-up per-target actor-local
/// grants on the extension path — the same limitation the libp2p
/// dispatch path has (it only probes actor-local for the registry).
#[derive(Clone, Debug)]
struct PropagatedCaller {
    caller: crate::actors::Caller,
    space_role: Option<u8>,
}

thread_local! {
    /// The caller of the invoke the native driver is *currently*
    /// handling on this agent's thread. `extension_thread` stamps it (via
    /// [`RelayCallerGuard`]) before driving an invoke-path `dispatch_and_poll`
    /// and clears it after; the `EFFECT_ASK` fulfiller reads its own
    /// thread's slot to relay the real caller (bounded by `intra_caps`). `Some`
    /// for an inbound invoke, `None` for self-originated work — the envelope
    /// path and a periodic `tick` leave it unstamped — which relays as
    /// `Unauthenticated`. Keyed implicitly by thread, so concurrent agents
    /// never clobber each other's caller.
    static RELAY_CALLER: core::cell::RefCell<Option<PropagatedCaller>> =
        const { core::cell::RefCell::new(None) };
}

/// RAII guard: stamp the current relay caller for the duration of one
/// native invoke dispatch, clearing it on drop. Drop runs even if the
/// dispatched handler panics (it unwinds past this guard's scope), so a
/// refused/exploding call never leaves a stale caller to poison the next
/// dispatch on this thread.
struct RelayCallerGuard;

impl RelayCallerGuard {
    fn stamp(pc: PropagatedCaller) -> Self {
        RELAY_CALLER.with(|c| *c.borrow_mut() = Some(pc));
        RelayCallerGuard
    }
}

impl Drop for RelayCallerGuard {
    fn drop(&mut self) {
        RELAY_CALLER.with(|c| *c.borrow_mut() = None);
    }
}

/// Read this thread's current relay caller, if an extension invoke
/// dispatch is in flight on it.
fn current_relay_caller() -> Option<PropagatedCaller> {
    RELAY_CALLER.with(|c| c.borrow().clone())
}

/// Well-known instance name of the space registry. Used by
/// [`VosNode::record_agent_name`] to seed the [`AgentNames`] reverse
/// map for the registry's fixed [`ServiceId::REGISTRY`] even when it's
/// registered from a bare `AgentConfig`, so the registry resolves
/// name-from-id through the same map as every other installed agent
/// rather than via a special case.
pub const REGISTRY_AGENT_NAME: &str = "space-registry";

/// Well-known instance name of the hyperspace (federation) registry
/// replica. The sync-serve gate hardcodes it to `Public` — the hyperspace
/// registry is the deliberately-ungated federation surface. Set on the
/// replica's `AgentConfig` at [`VosNode::attach_network`] so `slot.name`
/// carries it (a bare `AgentConfig` would leave the name empty).
pub const HYPERSPACE_REGISTRY_AGENT_NAME: &str = "hyperspace-registry";

/// Compute the `(caller, space_role byte)` relayed by a bounded outbound
/// `ctx.ask` to `target_name`. External callers use the intersection model:
/// `min(caller's space role, the declared cap ceiling)`, so the relay cannot
/// amplify them. A PVM actor may instead activate its own matching cap as an
/// autonomous principal. In every case, no matching cap means no authority.
/// The returned caller preserves an external peer/member identity or names the
/// cap-bearing PVM actor; native internal origins remain anonymous.
///
/// - No matching cap → `(Unauthenticated, None)`: the extension has
///   no authority for this target; role-gated handlers refuse.
/// - `propagated == None` from a native extension → `(Unauthenticated, None)`.
/// - `propagated == None` from a PVM actor with a matching cap → that actor's
///   authenticated identity plus the cap role. The cap is the explicit
///   operator grant that lets autonomous actors call protected extensions.
/// - Peer caller → relays the peer's identity + `min(space_role,
///   ceiling)`.
/// - An unauthenticated propagated caller is never amplified into actor
///   authority. System/Actor parents may activate the current PVM actor's own
///   explicit cap; native extensions still relay them anonymously.
fn resolve_relay_caller(
    propagated: Option<&PropagatedCaller>,
    caps: &[crate::actors::IntraCap],
    target_name: Option<&str>,
    actor_principal: Option<ServiceId>,
) -> (crate::actors::Caller, Option<u8>) {
    use crate::actors::{Caller, SpaceRole, cap_for};

    let Some(ceiling) = cap_for(caps, target_name) else {
        return (Caller::Unauthenticated, None);
    };
    let Some(pc) = propagated else {
        return actor_principal
            .map(|actor| (Caller::Actor(actor), Some(ceiling.as_u8())))
            .unwrap_or((Caller::Unauthenticated, None));
    };
    if matches!(pc.caller, Caller::Unauthenticated) {
        return (Caller::Unauthenticated, None);
    }
    if matches!(pc.caller, Caller::System | Caller::Actor(_))
        && let Some(actor) = actor_principal
    {
        return (Caller::Actor(actor), Some(ceiling.as_u8()));
    }
    // The caller's effective space-wide authority entering the relay.
    let carried = pc.space_role.and_then(SpaceRole::from_u8);
    let Some(carried) = carried else {
        return (Caller::Unauthenticated, None);
    };
    let effective = carried.min(ceiling);
    // Preserve externally authenticated identities for audit, request
    // ownership, and actor-local lookups. Internal origins from a native
    // extension remain anonymous; their explicit carried role is still capped.
    let carrier = match &pc.caller {
        Caller::Peer(bytes) => Caller::Peer(bytes.clone()),
        Caller::Member(subject) => Caller::Member(*subject),
        _ => Caller::Unauthenticated,
    };
    (carrier, Some(effective.as_u8()))
}

/// Outcome of a single extension dispatch. `Ok(bytes)` means the
/// handler completed with the given reply (`bytes` may be empty
/// for a `()` return). Failures distinguish a rejected message, which
/// leaves state untouched, from a handler panic, after which state must be
/// discarded. The exact `POLL_ERR_*` code is logged in `dispatch_and_poll`.
enum DispatchOutcome {
    Ok(Vec<u8>),
    /// The dynamic bytes were malformed or named no declared handler. Actor
    /// state was never borrowed and remains safe to retain.
    NoHandler,
    /// User handler code panicked after it may have mutated actor state. The
    /// worker must terminate without persisting or continuing from that state.
    Panicked,
}

/// Host-side context the extension thread hands to `handle_effect`
/// — bundles the proof-blob CAS with optional cross-node fan-out
/// and on-disk persistence.
struct BlobFetchCtx<'a> {
    proof_blobs: &'a ProofBlobStore,
    proof_blobs_dir: Option<&'a std::path::Path>,
    #[cfg(feature = "network")]
    shared_network: &'a SharedNetwork,
}

/// Upper bound an extension waits for an invoked actor's result.
const ASK_TIMEOUT: Duration = Duration::from_secs(300);

/// Leader-forwarding context for the extension ask path. Bundles the
/// shared network handle with the host's [`RaftHosts`] map so
/// [`route_invoke`] can recognize a follower-rejected write (the local
/// replica drops the reply when its commit fails NotLeader) and
/// re-address the invoke to the group's current leader over the wire.
/// `Default` is the inert form (no network, no raft hosts) used by
/// builds without the network/storage features and by tests.
#[derive(Clone, Default)]
struct RaftFwd {
    #[cfg(all(feature = "network", feature = "storage"))]
    network: SharedNetwork,
    #[cfg(all(feature = "network", feature = "storage"))]
    hosts: RaftHosts,
}

/// Outcome of awaiting the local invoke reply in [`route_invoke`].
/// `Canceled` (the target dropped its reply sender) is kept distinct
/// from `Timeout` and from a real envelope because it is the signature
/// of a Raft follower refusing a write — the one case worth retrying
/// against the group's leader. A handler panic also lands here; the
/// leader-role check in [`forward_to_raft_leader`] filters that out.
enum AskOutcome {
    Reply(Vec<u8>),
    Canceled,
    Timeout,
}

/// The async effect router handed to [`run_ext_task`].
///
/// Host effects are fulfilled asynchronously while the extension task is
/// parked. Actor asks use the invoke substrate so status and caller authority
/// are preserved.
struct Fulfiller<'a> {
    extension_id: ServiceId,
    /// Complete synchronous-invoke lineage through this extension, including
    /// the extension itself. Forwarding preserves it so cycles fail before a
    /// serial extension worker waits on its own queue.
    invoke_chain: &'a [u32],
    blob_fetch: &'a BlobFetchCtx<'a>,
    /// Outbound-invoke routing table. An extension's `ctx.ask` routes through
    /// the host invoke substrate
    /// (per-call async reply, status-framed, and able to reach PVM targets).
    invoke_routes: &'a InvokeRoutes,
    /// The extension's declared intra-system caps. An
    /// `EFFECT_ASK` relays the real caller of the invoke in flight
    /// (read from `RELAY_CALLER`), bounded by `min(caller role, cap ceiling)`
    /// for the target — never the `Caller::Actor` intra-system bypass — so a
    /// role-gated target (e.g. the registry's admin-gated `publish`) still
    /// consults the caller's real role.
    intra_caps: &'a [crate::actors::IntraCap],
    /// Host reverse map `local_id → instance_name` — resolves
    /// the ask target's name so `intra_caps` (declared by name) bind, and so
    /// the propagated peer's actor-local grant can be looked up.
    agent_names: &'a AgentNames,
    /// Leader-forwarding context for asks that target a raft-hosted
    /// agent whose local replica is a follower.
    raft_fwd: &'a RaftFwd,
}

impl Fulfiller<'_> {
    async fn fulfill(&mut self, effect: &[u8]) -> Vec<u8> {
        match effect.first().copied() {
            Some(crate::effects::EFFECT_ASK) => {
                let rest = &effect[1..];
                if rest.len() < 4 {
                    return crate::effects::result::err(crate::actors::run::STATUS_PANICKED);
                }
                let target = u32::from_le_bytes(rest[..4].try_into().unwrap());
                let target_name = self
                    .agent_names
                    .read()
                    .ok()
                    .and_then(|m| m.get(&local_id_of(target)).cloned());
                let propagated = current_relay_caller();
                let (caller, space_role) = resolve_relay_caller(
                    propagated.as_ref(),
                    self.intra_caps,
                    target_name.as_deref(),
                    None,
                );
                match route_invoke(
                    self.invoke_routes,
                    self.raft_fwd,
                    self.extension_id,
                    self.invoke_chain,
                    caller,
                    space_role,
                    None,
                    rest,
                )
                .await
                {
                    Ok(reply) => crate::effects::result::ok(&reply),
                    Err(status) => crate::effects::result::err(status),
                }
            }
            _ => handle_effect(effect, self.extension_id, self.blob_fetch),
        }
    }
}

/// Route `[target:u32 LE][payload]` through the host invoke substrate with a
/// per-call **async** reply (`ReplyChannel::Async`), awaited on the executor
/// (no blocking-pool thread, correlated per-call). `caller` + `space_role` +
/// `actor_local_role` are the relayed authority the caller already computed —
/// for an extension's `ctx.ask`, the *bounded* real caller
/// (`resolve_relay_caller`), NOT the `Caller::Actor` bypass, so a
/// role-gated target consults the caller's capped role. Returns the unwrapped reply
/// bytes on a `STATUS_DONE`/`STATUS_YIELDED` envelope (`Ok`, possibly empty
/// for a `()` return) or the target's failure status.
///
/// Raft targets get one extra move: when the target maps to a
/// raft-hosted agent (via `fwd.hosts`) and the local replica DROPS
/// the reply — a follower's commit fails NotLeader and
/// `handle_invoke_request` closes the channel — the invoke is
/// re-sent to the group's leader over libp2p. Reads never hit this
/// path (an unchanged-state commit short-circuits before the
/// propose, so followers answer them locally).
async fn route_invoke(
    invoke_routes: &InvokeRoutes,
    fwd: &RaftFwd,
    extension_id: ServiceId,
    invoke_chain: &[u32],
    caller: crate::actors::Caller,
    space_role: Option<u8>,
    actor_local_role: Option<u8>,
    rest: &[u8],
) -> Result<Vec<u8>, u8> {
    if rest.len() < 4 {
        return Err(crate::actors::run::STATUS_PANICKED);
    }
    let target = u32::from_le_bytes(rest[..4].try_into().unwrap());
    let payload = rest[4..].to_vec();

    match check_invoke_forward(invoke_chain, target) {
        InvokeForwardCheck::Allowed => {}
        InvokeForwardCheck::Cycle => {
            warn!(
                %extension_id,
                target,
                chain = ?invoke_chain,
                "extension invoke would form a cycle; aborting forward",
            );
            return Err(crate::actors::run::STATUS_PANICKED);
        }
        InvokeForwardCheck::DepthExceeded => {
            warn!(
                %extension_id,
                target,
                depth = invoke_chain.len(),
                cap = MAX_CROSS_AGENT_DEPTH,
                "extension invoke chain exceeded depth cap; aborting forward",
            );
            return Err(crate::actors::run::STATUS_PANICKED);
        }
    }

    // Route lookup with two-way prefix fallback against the local table:
    //
    // - **scoped→unscoped** (`target & 0xFFFF`): the registry's `resolve`
    //   returns a node-prefix-scoped id while special unscoped agents (the
    //   registry at local_id 0) register themselves bare. Mirrors
    //   `dispatch_invoke`.
    // - **unscoped→scoped** (`extension_prefix | local`): the inverse case an
    //   extension hits — the in-`.so` `Context::id()` carries no
    //   node prefix, so the extension passes `caller_prefix = 0` to the
    //   registry's `resolve`, which then hands back an *unscoped* id; but
    //   locally-registered agents live under the host's prefix. Re-scope with
    //   the calling extension's own prefix (the host knows it even though the
    //   `.so` doesn't) so a same-space dep resolves. A 0-prefix host collapses
    //   this to the unscoped form (harmless).
    let scoped = (extension_id.0 & 0xFFFF_0000) | (target & 0xFFFF);
    let (routed_target, tx) = {
        let map = invoke_routes
            .lock()
            .map_err(|_| crate::actors::run::STATUS_PANICKED)?;
        match map
            .get(&target)
            .map(|tx| (target, tx))
            .or_else(|| {
                let unscoped = target & 0xFFFF;
                map.get(&unscoped).map(|tx| (unscoped, tx))
            })
            .or_else(|| map.get(&scoped).map(|tx| (scoped, tx)))
        {
            Some((resolved, tx)) => (resolved, tx.clone()),
            None => {
                warn!(%extension_id, target, "ext ask: no route for target");
                return Err(crate::actors::run::STATUS_NOT_FOUND);
            }
        }
    };

    // Prefix fallback can resolve a different numeric ServiceId than the one
    // encoded by the extension. Check that concrete route too: otherwise
    // A(scoped) → B → A(unscoped) evades the raw-ID check above and queues a
    // request onto A while A is synchronously waiting for B.
    if routed_target != target {
        match check_invoke_forward(invoke_chain, routed_target) {
            InvokeForwardCheck::Allowed => {}
            InvokeForwardCheck::Cycle => {
                warn!(
                    %extension_id,
                    target,
                    routed_target,
                    chain = ?invoke_chain,
                    "extension invoke fallback would form a cycle; aborting forward",
                );
                return Err(crate::actors::run::STATUS_PANICKED);
            }
            InvokeForwardCheck::DepthExceeded => {
                // The raw target passed the same depth check above.
                unreachable!("invoke depth result changed while resolving a route")
            }
        }
    }

    // Snapshot the forward plan up front (and clone the payload only
    // when one exists) — the local send consumes `payload`.
    let forward_plan =
        raft_forward_plan(fwd, extension_id, target).map(|rep| (rep, payload.clone()));

    let (reply_tx, reply_rx) = futures_channel::oneshot::channel::<Vec<u8>>();
    if tx
        .send(InvokeRequest {
            caller,
            space_role,
            actor_local_role,
            #[cfg(all(feature = "network", feature = "storage"))]
            delegated_origin: None,
            role_authority_request: false,
            root_upgrade_request: false,
            invocation_id: None,
            native_call: None,
            msg: payload,
            reply: ReplyChannel::Async(reply_tx),
            chain: invoke_chain.to_vec(),
        })
        .is_err()
    {
        return Err(crate::actors::run::STATUS_NOT_FOUND);
    }

    // Await the reply on the executor, raced against a timeout — no thread is
    // blocked, so sibling tasks keep running while we wait. A dropped
    // sender (Canceled) is kept distinct from the timeout: it is the
    // signature of a follower refusing a write.
    let outcome = futures_lite::future::or(
        async {
            match reply_rx.await {
                Ok(env) => AskOutcome::Reply(env),
                Err(_) => AskOutcome::Canceled,
            }
        },
        async {
            async_io::Timer::after(ASK_TIMEOUT).await;
            AskOutcome::Timeout
        },
    )
    .await;

    match outcome {
        AskOutcome::Reply(env) => {
            #[cfg(all(feature = "network", feature = "storage"))]
            if let Some(redirect) = decode_service_raft_redirect(&env) {
                return match forward_plan {
                    Some((rep_id, payload)) => forward_to_raft_leader(
                        fwd,
                        extension_id,
                        target,
                        rep_id,
                        invoke_chain,
                        payload,
                        Some(redirect.origin),
                    )
                    .await
                    .ok_or(crate::actors::run::STATUS_PANICKED),
                    None => Err(crate::actors::run::STATUS_PANICKED),
                };
            }
            unwrap_invoke_envelope_result(&env)
        }
        AskOutcome::Timeout => Err(crate::actors::run::STATUS_PANICKED),
        AskOutcome::Canceled => match forward_plan {
            Some((rep_id, payload)) => forward_to_raft_leader(
                fwd,
                extension_id,
                target,
                rep_id,
                invoke_chain,
                payload,
                None,
            )
            .await
            .ok_or(crate::actors::run::STATUS_PANICKED),
            None => Err(crate::actors::run::STATUS_PANICKED),
        },
    }
}

/// Look the ask target up in the host's raft map (same three-key
/// fallback the route lookup uses). `Some(rep_id)` means the target
/// is served by a local multi-mode Raft worker and a dropped reply
/// is worth retrying against the group's leader.
#[cfg(all(feature = "network", feature = "storage"))]
fn raft_forward_plan(fwd: &RaftFwd, extension_id: ServiceId, target: u32) -> Option<[u8; 32]> {
    let scoped = (extension_id.0 & 0xFFFF_0000) | (target & 0xFFFF);
    let map = fwd.hosts.lock().ok()?;
    map.get(&target)
        .or_else(|| map.get(&(target & 0xFFFF)))
        .or_else(|| map.get(&scoped))
        .copied()
}

#[cfg(not(all(feature = "network", feature = "storage")))]
fn raft_forward_plan(_fwd: &RaftFwd, _extension_id: ServiceId, _target: u32) -> Option<[u8; 32]> {
    None
}

/// Upper bound on the wire wait for a leader-forwarded invoke. The
/// leader's quorum wait is bounded by the 5 s propose timeout
/// (`RaftConfig::propose_timeout_ms`); 3× that covers a retry plus
/// transit without stacking anywhere near the 300 s `ASK_TIMEOUT` —
/// a wedged group should surface as a failed ask in seconds, and the
/// app-level retry owns what happens next.
#[cfg(all(feature = "network", feature = "storage"))]
const RAFT_FORWARD_TIMEOUT: Duration = Duration::from_secs(15);

/// Re-send a follower-dropped invoke to the Raft group's current
/// leader. Consults the LOCAL worker first: the forward only fires
/// when this replica is genuinely not the leader and knows who is —
/// which also filters out the other reply-drop cause (a handler
/// panic on a leader replica shows `role == Leader` and stays a
/// local failure, as before).
///
/// The reply comes back as raw bytes the remote side already
/// unwrapped (`NodeService::dispatch_invoke`), so no second unwrap
/// here. Empty bytes are indistinguishable from a remote failure and
/// collapse to `None` — raft write verbs must return a non-empty
/// reply (statuses/structs do; a bare `()` doesn't). A verbatim
/// STATUS_FORBIDDEN envelope maps to `None` for parity with the
/// local path. Caller authority on the leader is the FORWARDING
/// NODE's peer role — operators must grant member tier to a voter
/// node's peer for its forwarded writes to pass role gates.
#[cfg(all(feature = "network", feature = "storage"))]
/// Synchronous leader-forward for the agent thread's (blocking) outbound-invoke
/// path: the agent analogue of the async [`forward_to_raft_leader`] the
/// extension ask path uses. Re-sends a follower-dropped raft write to the
/// current leader and blocks on the reply.
#[cfg(all(feature = "network", feature = "storage"))]
fn agent_forward_to_raft_leader(
    fwd: &RaftFwd,
    from_id: ServiceId,
    target: u32,
    rep_id: [u8; 32],
    mut payload: Vec<u8>,
    delegated_origin: Option<crate::service::Origin>,
) -> Option<Vec<u8>> {
    let net = fwd.network.lock().ok()?.clone()?;
    let st = net.local_raft_status(&rep_id)?;
    if st.role == crate::network::RaftRole::Leader {
        return None;
    }
    let leader = st.leader_hint?;
    if leader == net.local_prefix() {
        // Hint says us but we aren't Leader — election in flight; let the
        // app-level retry pick it up.
        return None;
    }
    let peer = net.peer_for_prefix(leader)?;
    let to = ((leader as u32) << 16) | (target & 0xFFFF);
    if let Some(origin) = delegated_origin {
        payload = encode_service_raft_delegation(origin, false, false, false, &payload);
    }
    debug!(%from_id, target, leader, "agent ask: forwarding follower-dropped raft write to leader");
    let rx = net.send_invoke(peer, from_id.0, to, Vec::new(), payload);
    match rx.recv_timeout(RAFT_FORWARD_TIMEOUT) {
        Ok(bytes)
            if !bytes.is_empty()
                && bytes.first().copied() != Some(crate::actors::run::STATUS_FORBIDDEN) =>
        {
            Some(bytes)
        }
        _ => None,
    }
}

#[cfg(all(feature = "network", feature = "storage"))]
async fn forward_to_raft_leader(
    fwd: &RaftFwd,
    extension_id: ServiceId,
    target: u32,
    rep_id: [u8; 32],
    invoke_chain: &[u32],
    mut payload: Vec<u8>,
    delegated_origin: Option<crate::service::Origin>,
) -> Option<Vec<u8>> {
    let net = fwd.network.lock().ok()?.clone()?;
    let st = net.local_raft_status(&rep_id)?;
    if st.role == crate::network::RaftRole::Leader {
        return None;
    }
    let leader = st.leader_hint?;
    if leader == net.local_prefix() {
        // Hint says us but the worker isn't Leader — election in
        // flight; let the app-level retry pick it up.
        return None;
    }
    let peer = net.peer_for_prefix(leader)?;
    let to = ((leader as u32) << 16) | (target & 0xFFFF);
    if let Some(origin) = delegated_origin {
        payload = encode_service_raft_delegation(origin, false, false, false, &payload);
    }
    debug!(
        %extension_id, target, leader,
        "ext ask: forwarding follower-dropped raft write to leader"
    );
    let rx = net.send_invoke(peer, extension_id.0, to, invoke_chain.to_vec(), payload);
    // Poll the sync receiver cooperatively — the swarm thread fills
    // it; this task yields between polls so sibling tasks keep
    // running.
    let deadline = Instant::now() + RAFT_FORWARD_TIMEOUT;
    loop {
        match rx.try_recv() {
            Ok(bytes) => {
                if bytes.is_empty()
                    || bytes.first().copied() == Some(crate::actors::run::STATUS_FORBIDDEN)
                {
                    return None;
                }
                return Some(bytes);
            }
            Err(mpsc::TryRecvError::Disconnected) => return None,
            Err(mpsc::TryRecvError::Empty) => {
                if Instant::now() >= deadline {
                    warn!(%extension_id, target, leader, "ext ask: leader forward timed out");
                    return None;
                }
                async_io::Timer::after(Duration::from_millis(25)).await;
            }
        }
    }
}

#[cfg(not(all(feature = "network", feature = "storage")))]
async fn forward_to_raft_leader(
    _fwd: &RaftFwd,
    _extension_id: ServiceId,
    _target: u32,
    _rep_id: [u8; 32],
    _invoke_chain: &[u32],
    _payload: Vec<u8>,
    _delegated_origin: Option<crate::service::Origin>,
) -> Option<Vec<u8>> {
    None
}

/// Drive one extension task to completion on the host executor: poll it,
/// fulfil each effect it parks on, until it is READY / PANIC. The `.so`'s
/// `task_poll` advances the future (the host never polls a `.so` future
/// directly — vtable layout is not a stable cross-artifact ABI).
async fn run_ext_task(
    instance: &mut crate::extension::ExtensionInstance<'_>,
    handle: u64,
    fulfiller: &mut Fulfiller<'_>,
) -> DispatchOutcome {
    use crate::extension::TaskOutcome;

    let extension_id = fulfiller.extension_id;

    // Free the task slot on EVERY exit path — including an unwind from a
    // panicking effect fulfilment — not just the normal READY/PANIC returns.
    // (The instance's own Drop is the ultimate backstop: it clears the whole
    // slab before the actor, so no future ever outlives the actor regardless.)
    struct TaskGuard<'i, 'p> {
        inst: &'i mut crate::extension::ExtensionInstance<'p>,
        handle: u64,
        done: bool,
    }
    impl TaskGuard<'_, '_> {
        fn finish(&mut self) {
            if !self.done {
                self.inst.drop_task(self.handle);
                self.done = true;
            }
        }
    }
    impl Drop for TaskGuard<'_, '_> {
        fn drop(&mut self) {
            if !self.done {
                self.inst.drop_task(self.handle);
            }
        }
    }

    let mut guard = TaskGuard {
        inst: instance,
        handle,
        done: false,
    };
    let mut result: Vec<u8> = Vec::new();
    let outcome = loop {
        match guard.inst.poll_task(handle, &result) {
            TaskOutcome::Ready(reply) => break DispatchOutcome::Ok(reply),
            TaskOutcome::Pending(effect) => {
                result = fulfiller.fulfill(&effect).await;
            }
            TaskOutcome::Panic => {
                error!(%extension_id, "extension: task panicked during dispatch");
                break DispatchOutcome::Panicked;
            }
        }
    };
    guard.finish();
    outcome
}

/// Encode the host's synthetic periodic-tick message — a bare `tick` dynamic
/// `Msg` with no args, framed exactly like an inbound invoke (a `TAG_DYNAMIC`
/// byte followed by the encoded `Msg`) so the actor's macro-generated
/// `deliver` routes it to its `#[msg] async fn tick(&mut self, ctx)` handler.
fn encode_tick_payload() -> Vec<u8> {
    use crate::actors::codec::Encode;
    use crate::value::{Msg, TAG_DYNAMIC};
    let msg = Msg::new("tick");
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

/// Dispatch a message to a native extension instance and drive it to
/// completion on the host executor `ex`. Returns the reply bytes on success or
/// `DispatchOutcome::Panicked` on a poisoned future or `NoHandler` when the
/// dynamic bytes cannot construct a declared handler.
#[allow(clippy::too_many_arguments)]
fn dispatch_and_poll(
    ex: &async_executor::LocalExecutor<'_>,
    instance: &mut crate::extension::ExtensionInstance<'_>,
    msg: &[u8],
    task_context: crate::extension::ExtensionInvocationContext,
    extension_id: ServiceId,
    invoke_chain: &[u32],
    blob_fetch: &BlobFetchCtx<'_>,
    invoke_routes: &InvokeRoutes,
    intra_caps: &[crate::actors::IntraCap],
    agent_names: &AgentNames,
    raft_fwd: &RaftFwd,
) -> DispatchOutcome {
    // Dispatch stays N=1: build exactly one root task and run it to completion
    // before the next message. Running a second root task while this one holds
    // `&mut actor` would alias — concurrency is reserved for the `&self` service
    // model (later phases).
    let handle = instance.new_task_with_context(msg, &task_context);
    if handle == 0 {
        // No handler matched (unknown / undecodable method) — the old
        // POLL_ERR_NO_FUTURE / "went idle" path.
        error!(%extension_id, "extension: no handler matched message");
        return DispatchOutcome::NoHandler;
    }

    let mut fulfiller = Fulfiller {
        extension_id,
        invoke_chain,
        blob_fetch,
        invoke_routes,
        intra_caps,
        agent_names,
        raft_fwd,
    };
    // block_on(ex.run(..)) drives the root task (and any future spawned tasks)
    // on this thread — the one that owns the instance. Extensions spawn none.
    async_io::block_on(ex.run(run_ext_task(instance, handle, &mut fulfiller)))
}

/// Fulfill a host I/O effect. Dispatches by the effect tag byte.
fn handle_effect(effect: &[u8], extension_id: ServiceId, blob_fetch: &BlobFetchCtx<'_>) -> Vec<u8> {
    use crate::effects::{EFFECT_BLOB_GET, EFFECT_BLOB_PUT, EFFECT_FETCH};

    if effect.is_empty() {
        return Vec::new();
    }
    let tag = effect[0];
    let rest = &effect[1..];

    match tag {
        EFFECT_FETCH => {
            #[cfg(feature = "http-client")]
            {
                handle_fetch(rest)
            }
            #[cfg(not(feature = "http-client"))]
            {
                let _ = rest;
                crate::effects::FetchResponse::host_error(
                    "vos: built without 'http-client' feature — EFFECT_FETCH unavailable",
                )
                .encode()
            }
        }
        EFFECT_BLOB_GET => handle_blob_get(rest, blob_fetch),
        EFFECT_BLOB_PUT => handle_blob_put(rest, blob_fetch),
        other => {
            error!(%extension_id, tag = format!("{other:#04x}"), "extension: unknown effect tag");
            Vec::new()
        }
    }
}

/// Serve `EFFECT_BLOB_GET`. Payload =
/// `[hash: 32 bytes][hint_prefix: u16 LE]` (older callers that
/// predate the hint field still work — missing trailing bytes
/// decode as `hint_prefix = 0` = no hint). Returns the stored
/// bytes when the hash is in the local proof-blob store (hot
/// cache or disk); on miss falls through to a libp2p fan-out
/// — targeting the hinted peer first when one is supplied, then
/// every other known peer as a fallback. First peer that has the
/// blob wins; successful fetches populate both the hot cache AND
/// disk (when configured) so the next lookup short-circuits.
/// Empty bytes signal "no peer has it" — the caller surfaces it
/// as a verification reject.
fn handle_blob_get(rest: &[u8], blob_fetch: &BlobFetchCtx<'_>) -> Vec<u8> {
    if rest.len() < 32 {
        return Vec::new();
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&rest[..32]);
    let hint_prefix = if rest.len() >= 34 {
        u16::from_le_bytes([rest[32], rest[33]])
    } else {
        0
    };

    // Hot-cache hit — fast path.
    if let Some(bytes) = blob_fetch
        .proof_blobs
        .read()
        .ok()
        .and_then(|store| store.get(&hash).cloned())
    {
        return bytes;
    }

    // Disk fallback — survives restarts.
    if let Some(dir) = blob_fetch.proof_blobs_dir
        && let Ok(bytes) = std::fs::read(dir.join(proof_blob_filename(&hash)))
    {
        cache_blob(&hash, &bytes, blob_fetch);
        return bytes;
    }

    // Local miss — try the hinted peer first if any, then fan
    // out across the remaining known peers. Both legs share the
    // same `BLOB_FETCH_PEER_TIMEOUT` budget; the hint just gets
    // the first slice of it.
    #[cfg(feature = "network")]
    {
        let net = blob_fetch
            .shared_network
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(net) = net {
            let deadline = Instant::now() + BLOB_FETCH_PEER_TIMEOUT;
            let hint_peer = if hint_prefix != 0 {
                net.peer_for_prefix(hint_prefix)
            } else {
                None
            };

            // Hint leg — single targeted request. Short-circuits
            // the whole call when the hint is right (the common
            // case in production: the requester knows which peer
            // produced the proof).
            if let Some(peer) = hint_peer {
                let rx = net.send_fetch_proof_blob(peer, hash);
                if let Ok(Some(bytes)) = rx.recv_timeout(BLOB_HINT_LEG_TIMEOUT) {
                    cache_blob(&hash, &bytes, blob_fetch);
                    return bytes;
                }
            }

            // Fan-out leg — race every other connected peer.
            let peers: Vec<_> = net
                .connected_peers()
                .into_iter()
                .filter(|p| Some(*p) != hint_peer)
                .collect();
            if !peers.is_empty() {
                let mut receivers: Vec<_> = peers
                    .into_iter()
                    .map(|peer| net.send_fetch_proof_blob(peer, hash))
                    .collect();
                while !receivers.is_empty() {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    let poll_slice = remaining.min(Duration::from_millis(50));
                    let mut hit = None;
                    let mut still_open: Vec<_> = Vec::with_capacity(receivers.len());
                    for rx in receivers.drain(..) {
                        match rx.recv_timeout(poll_slice) {
                            Ok(Some(bytes)) => {
                                hit = Some(bytes);
                                break;
                            }
                            Ok(None) => {}
                            Err(mpsc::RecvTimeoutError::Timeout) => still_open.push(rx),
                            Err(mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                    }
                    if let Some(bytes) = hit {
                        cache_blob(&hash, &bytes, blob_fetch);
                        return bytes;
                    }
                    receivers = still_open;
                }
            }
        }
    }

    // Reference `hint_prefix` so the no-network build path
    // doesn't trip the `unused_variable` lint.
    #[cfg(not(feature = "network"))]
    let _ = hint_prefix;

    Vec::new()
}

/// Serve `EFFECT_BLOB_PUT`. Payload = the raw blob bytes. Stores
/// them into the same proof-blob CAS `EFFECT_BLOB_GET` reads —
/// hot cache plus write-through disk when configured, the exact
/// tiers `VosNode::put_proof_blob` writes and under the same
/// content addressing (`proof_blob_hash`) — and returns the
/// 32-byte hash. The put is node-local; peers obtain the blob on
/// demand via the existing `handle_blob_get` fan-out (no push).
/// Store failures degrade the same way `put_proof_blob`'s do: the
/// hash is still returned and only the missing tier is lost.
fn handle_blob_put(rest: &[u8], blob_fetch: &BlobFetchCtx<'_>) -> Vec<u8> {
    let hash = proof_blob_hash(rest);
    cache_blob(&hash, rest, blob_fetch);
    hash.to_vec()
}

/// Populate hot cache + (when configured) write-through disk on
/// a successful cross-tier hit. Failures are logged and dropped
/// — the caller already has the bytes, so the local request
/// succeeds; only persistence/caching for the next request
/// degrades.
fn cache_blob(hash: &[u8; 32], bytes: &[u8], blob_fetch: &BlobFetchCtx<'_>) {
    if let Ok(mut store) = blob_fetch.proof_blobs.write() {
        store.insert(*hash, bytes.to_vec());
    }
    if let Some(dir) = blob_fetch.proof_blobs_dir {
        let path = dir.join(proof_blob_filename(hash));
        if !path.exists()
            && let Err(e) = std::fs::write(&path, bytes)
        {
            warn!(
                error = %e,
                path = %path.display(),
                "proof_blobs: disk write-through failed",
            );
        }
    }
}

/// Total wall-clock budget for the cross-node fan-out path in
/// `handle_blob_get`. STARK proofs are ~1.4 MiB on LAN today —
/// half a second is comfortable headroom for a single hop without
/// extending the federation test's overall runtime noticeably.
#[cfg(feature = "network")]
const BLOB_FETCH_PEER_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Budget for the hint leg specifically — the targeted request to
/// the peer the caller named. Tight on purpose: when the hint is
/// wrong (or the hinted peer is offline) we want to fall through
/// to the fan-out quickly rather than burning the whole
/// `BLOB_FETCH_PEER_TIMEOUT` on a dead path.
#[cfg(feature = "network")]
const BLOB_HINT_LEG_TIMEOUT: Duration = Duration::from_millis(750);

/// Perform an HTTP request via ureq. Blocking; runs on the worker thread.
#[cfg(feature = "http-client")]
fn handle_fetch(payload: &[u8]) -> Vec<u8> {
    use crate::effects::{FetchRequest, FetchResponse, HttpMethod};

    let Some(req) = FetchRequest::decode(payload) else {
        return FetchResponse::host_error("malformed FetchRequest").encode();
    };

    let mut ureq_req = match req.method {
        HttpMethod::Get => ureq::get(&req.url),
        HttpMethod::Post => ureq::post(&req.url),
        HttpMethod::Put => ureq::put(&req.url),
        HttpMethod::Delete => ureq::delete(&req.url),
        HttpMethod::Patch => ureq::patch(&req.url),
        HttpMethod::Head => ureq::head(&req.url),
        HttpMethod::Options => ureq::request("OPTIONS", &req.url),
    };
    for (name, value) in &req.headers {
        ureq_req = ureq_req.set(name, value);
    }

    let result = if req.body.is_empty() {
        ureq_req.call()
    } else {
        ureq_req.send_bytes(&req.body)
    };

    let response = match result {
        Ok(r) => ureq_response_to(r),
        Err(ureq::Error::Status(code, r)) => {
            let mut resp = ureq_response_to(r);
            resp.status = code;
            resp
        }
        Err(e) => FetchResponse::host_error(format!("network error: {e}")),
    };

    response.encode()
}

#[cfg(feature = "http-client")]
fn ureq_response_to(r: ureq::Response) -> crate::effects::FetchResponse {
    use crate::effects::FetchResponse;
    let status = r.status();
    let headers: Vec<(String, String)> = r
        .headers_names()
        .into_iter()
        .filter_map(|n| r.header(&n).map(|v| (n, v.to_string())))
        .collect();
    let mut body = Vec::new();
    let _ = std::io::Read::read_to_end(&mut r.into_reader(), &mut body);
    FetchResponse {
        status,
        headers,
        body,
    }
}

// ── State persistence ───────────────────────────────────────────────

/// Pick the worker's commit strategy from its config.
///
/// Workers never get CRDT or Raft commits — they live outside the
/// deterministic universe. If a data directory is configured and the
/// `storage` feature is on, use [`LocalCommit`]; otherwise use [`NoCommit`]
/// (state is held in memory only). A configured persistence path is
/// fail-closed: path creation or database-open errors abort the worker.
///
/// [`LocalCommit`]: crate::commit::LocalCommit
/// [`NoCommit`]: crate::commit::NoCommit
fn build_extension_strategy(
    config: &ExtensionConfig,
) -> Result<Box<dyn crate::commit::CommitStrategy>, String> {
    #[cfg(feature = "storage")]
    {
        let path = config
            .db_path()
            .map_err(|error| format!("derive extension state path: {error}"))?;
        if let Some(path) = path {
            let strategy = crate::commit::LocalCommit::open(&path)
                .map_err(|error| format!("open extension state {}: {error}", path.display()))?;
            return Ok(Box::new(strategy));
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = config;
    }
    Ok(Box::new(crate::commit::NoCommit))
}

/// Serialize the worker's state and hand it to the commit strategy.
fn persist(
    strategy: &mut dyn crate::commit::CommitStrategy,
    instance: &crate::extension::ExtensionInstance<'_>,
) -> Result<(), crate::commit::CommitError> {
    let bytes = instance
        .save_state()
        .map_err(crate::commit::CommitError::Config)?;
    strategy.commit_state(&bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_replay_log(message: crate::value::Msg) -> crate::effect_log::EffectLog {
        use crate::Encode as _;

        let mut payload = vec![crate::value::TAG_DYNAMIC];
        payload.extend_from_slice(&message.encode());
        crate::effect_log::EffectLog::for_msg(payload)
    }

    #[test]
    fn registry_replay_rejects_malformed_dynamic_archives() {
        let malformed = crate::effect_log::EffectLog::for_msg(vec![
            crate::value::TAG_DYNAMIC,
            0xff,
            0x00,
            0x01,
        ]);
        assert!(registry_replay_request(&malformed).is_err());
    }

    #[test]
    fn registry_replay_default_denies_non_requests_and_misshapen_methods() {
        let nondynamic = crate::effect_log::EffectLog::for_msg(b"reply bytes".to_vec());
        assert!(registry_replay_request(&nondynamic).is_err());

        let unknown = registry_replay_log(crate::value::Msg::new("future_or_forged_method"));
        assert!(registry_replay_request(&unknown).is_err());

        let missing = registry_replay_log(crate::value::Msg::new("set_space_id"));
        assert!(registry_replay_request(&missing).is_err());

        let wrong_type = registry_replay_log(
            crate::value::Msg::new("set_space_id").with("space_id", "not bytes"),
        );
        assert!(registry_replay_request(&wrong_type).is_err());

        let extra = registry_replay_log(
            crate::value::Msg::new("set_space_id")
                .with("space_id", vec![1u8; 32])
                .with("unexpected", true),
        );
        assert!(registry_replay_request(&extra).is_err());

        let duplicate = registry_replay_log(
            crate::value::Msg::new("set_space_id")
                .with("space_id", vec![1u8; 32])
                .with("space_id", vec![1u8; 32]),
        );
        assert!(registry_replay_request(&duplicate).is_err());
    }

    #[test]
    fn registry_replay_rejects_impossible_effect_transcripts() {
        let mut reply = registry_replay_log(crate::value::Msg::new("protocol"));
        reply.record_reply(vec![1, 2, 3]);
        assert!(registry_replay_request(&reply).is_err());

        let mut child_result = registry_replay_log(crate::value::Msg::new("protocol"));
        child_result
            .invoke_effects
            .push(crate::effect_log::InvokeEffects {
                reply_idx: 0,
                svc_id: 1,
                effects: vec![],
            });
        assert!(registry_replay_request(&child_result).is_err());
    }

    #[test]
    fn registry_replay_accepts_kicks_and_legitimate_host_record_fields() {
        assert!(matches!(
            registry_replay_request(&crate::effect_log::EffectLog::for_msg(Vec::new())),
            Ok(None),
        ));

        let mut request = registry_replay_log(crate::value::Msg::new("protocol"));
        request.set_anchor(crate::refine_payload::ANCHOR_SMT_ROOT, [0x51; 32]);
        request.set_caller_prefix([0, 1, 3, 1, 2]);
        request.set_invocation_id(crate::service::InvocationId::new([0x52; 32]));
        assert!(matches!(
            registry_replay_request(&request),
            Ok(Some(message)) if message.name == "protocol"
        ));
    }

    struct NoAgentTrust;

    impl crate::agent::driver::AgentTrustProvider for NoAgentTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            None
        }

        fn authority_for_space(
            &self,
            _space: crate::service::SpaceId,
        ) -> Option<crate::agent::authority::AgentAuthorityBinding> {
            None
        }

        fn verify_package(
            &self,
            _agent: &crate::agent::AgentConfig,
            _package: &crate::agent::package::Package,
        ) -> bool {
            false
        }
    }

    struct NoAgentMerge(crate::service::NodeId);

    impl crate::agent::host::LocalMergeAuthenticator for NoAgentMerge {
        fn node(&self) -> crate::service::NodeId {
            self.0
        }

        fn sign_event(&self, _event: &mut crate::agent::journal::MergeEvent) -> bool {
            false
        }

        fn verify_event(&self, _event: &crate::agent::journal::MergeEvent) -> bool {
            false
        }
    }

    struct NoAgentGenesis;

    impl crate::agent::bootstrap::SystemAgentGenesisProvider for NoAgentGenesis {
        fn create(
            &self,
            _proposal: &crate::agent::bootstrap::SystemAgentGenesisProposal,
            _catalog: &[crate::agent::execution::RuntimeBlob],
        ) -> Result<
            crate::agent::bootstrap::SystemAgentGenesisProvision,
            crate::agent::bootstrap::SystemAgentGenesisProviderError,
        > {
            Err(crate::agent::bootstrap::SystemAgentGenesisProviderError::NotConfigured)
        }

        fn reproduce(
            &self,
            _locator: crate::agent::bootstrap::SystemAgentGenesisLocator,
        ) -> Result<
            crate::agent::bootstrap::SystemAgentGenesisProvision,
            crate::agent::bootstrap::SystemAgentGenesisProviderError,
        > {
            Err(crate::agent::bootstrap::SystemAgentGenesisProviderError::NotConfigured)
        }

        fn load_catalog(
            &self,
            _locator: crate::agent::bootstrap::SystemAgentGenesisLocator,
            _reference: &crate::service::BlobRef,
        ) -> Result<Option<Vec<u8>>, crate::agent::bootstrap::SystemAgentGenesisProviderError>
        {
            Ok(None)
        }
    }

    fn inert_agent_root_pins(
        scope: crate::agent::host::AgentHostScope,
    ) -> crate::agent::committee::RootAnchorPins {
        use crate::agent::committee::{
            AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
            AuthorityCommitteeMember, AuthorityMemberRole, RootAnchorPins, RootAnchorRecord,
        };

        let authority_binding = crate::service::Hash([0x41; 32]);
        let committee = AuthorityCommittee::new(
            scope.space,
            authority_binding,
            1,
            None,
            vec![
                AuthorityCommitteeMember::new(
                    crate::service::NodeId([0x42; 32]),
                    [0x43; 32],
                    AuthorityMemberRole::Voter,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let record = RootAnchorRecord::new(
            1,
            scope.space,
            crate::service::AgentId([0x44; 32]),
            authority_binding,
            crate::service::Hash([0x45; 32]),
            committee,
        )
        .unwrap();
        let genesis_claim = AuthorityClaimCommitment::from_payload_commitment(
            AuthorityClaimDomain::SystemAgentGenesis,
            1,
            crate::service::Hash([0x46; 32]),
        )
        .unwrap();
        RootAnchorPins::new(
            record.clone(),
            record.config_version(),
            record.id(),
            record.config_commitment(),
            genesis_claim,
        )
        .unwrap()
    }

    struct RemoveAgentHostDirectory(std::path::PathBuf);

    impl Drop for RemoveAgentHostDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn empty_agent_host_control(
        suffix: &str,
    ) -> (
        crate::agent::host::AgentHostControl,
        RemoveAgentHostDirectory,
    ) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "vos-node-agent-host-{suffix}-{}-{unique}",
            std::process::id()
        ));
        let remove = RemoveAgentHostDirectory(base.clone());
        std::fs::create_dir(&base).unwrap();
        let scope = crate::agent::host::AgentHostScope {
            space: crate::service::SpaceId([0x31; 32]),
            node: crate::service::NodeId([0x32; 32]),
        };
        let lease = crate::agent::host::AgentHostRootLease::acquire(
            base.join("data"),
            base.join("owner.lock"),
            scope,
        )
        .unwrap();
        let control = crate::agent::host::AgentHostControl::open(
            lease,
            Arc::new(NoAgentTrust),
            Arc::new(NoAgentMerge(scope.node)),
            Arc::new(NoAgentGenesis),
            inert_agent_root_pins(scope),
        )
        .unwrap();
        (control, remove)
    }

    fn missing_agent_invocation(
        agent: crate::service::AgentId,
    ) -> (
        crate::agent::execution::ActorInvocation,
        crate::agent::authority::ActorInvocationReceipt,
    ) {
        let public_key = crate::agent::authority::ed25519_public_key_wire([0x51; 32]);
        let authority = crate::agent::authority::AgentAuthorityBinding {
            agent,
            actor: crate::service::ActorId([0x52; 32]),
            deployment: crate::service::DeploymentId([0x53; 32]),
            program: crate::service::ProgramId([0x54; 32]),
            producer: crate::service::ProducerId::of_public_key(&public_key),
            public_key,
        };
        let auth = crate::agent::execution::ActorInvocationAuth::anonymous();
        let invocation = crate::agent::execution::ActorInvocation {
            invocation: crate::service::InvocationId([0x55; 32]),
            actor: crate::service::ActorId([0x56; 32]),
            incarnation: crate::service::Hash([0x57; 32]),
            deployment: crate::service::DeploymentId([0x58; 32]),
            program: crate::service::ProgramId([0x59; 32]),
            mode: crate::agent::MethodMode::Query,
            auth: auth.clone(),
            message: vec![0x5a],
            availability: Vec::new(),
            gas: 1,
        };
        let receipt = crate::agent::authority::ActorInvocationReceipt {
            claim: crate::agent::authority::ActorInvocationClaim {
                authority,
                space: crate::service::SpaceId([0x31; 32]),
                agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth,
                valid_from: 1,
                valid_until: 2,
            },
            signature: vec![0; crate::agent::authority::ED25519_SIGNATURE_BYTES],
        };
        (invocation, receipt)
    }

    #[test]
    fn local_agent_node_surface_forwards_only_settled_full_id_operations() {
        let agent = crate::service::AgentId([0x61; 32]);
        let (invocation, receipt) = missing_agent_invocation(agent);
        let mut node = VosNode::new();
        assert_eq!(
            node.invoke_local_agent_synchronous(agent, invocation.clone(), receipt.clone()),
            Err(crate::agent::host::AgentHostError::Unavailable),
        );
        assert_eq!(
            node.acknowledge_local_agent_invocation_synchronous(
                agent,
                invocation.clone(),
                receipt.clone(),
            ),
            Err(crate::agent::host::AgentHostError::Unavailable),
        );

        let (control, _remove) = empty_agent_host_control("settled-forwarding");
        node.attach_local_agent_host(control).unwrap();
        assert_eq!(
            node.invoke_local_agent_synchronous(agent, invocation.clone(), receipt.clone()),
            Err(crate::agent::host::AgentHostError::AgentNotFound),
        );
        assert_eq!(
            node.acknowledge_local_agent_invocation_synchronous(agent, invocation, receipt),
            Err(crate::agent::host::AgentHostError::AgentNotFound),
        );
        node.collect_checked().unwrap();
    }

    #[test]
    fn local_agent_host_is_single_owner_and_keeps_an_empty_node_alive() {
        let (control, _remove) = empty_agent_host_control("primary");
        let (duplicate, _remove_duplicate) = empty_agent_host_control("duplicate");
        let (stopped, _remove_stopped) = empty_agent_host_control("stopped");
        stopped.request_shutdown();
        let mut node = VosNode::new();
        assert!(node.attach_local_agent_host(stopped).is_err());
        let handle = control.handle_for_test();
        node.attach_local_agent_host(control).unwrap();
        assert!(node.attach_local_agent_host(duplicate).is_err());

        let mut ticks = 0;
        node.run_forever_with(|node| {
            ticks += 1;
            assert!(node.local_agent_host.as_ref().unwrap().identities().is_ok());
            node.shutdown_handle().store(true, Ordering::Release);
        });
        assert_eq!(ticks, 1, "the Local Agent host kept the router alive");
        assert!(
            !handle.is_running(),
            "the router epilogue fans a raw shutdown handle out to the Agent host"
        );
        node.collect();
        assert_eq!(
            handle.identities(),
            Err(crate::agent::host::AgentHostError::WorkerStopped)
        );
    }

    #[test]
    fn checked_node_collection_surfaces_an_agent_host_worker_crash() {
        let (control, _remove) = empty_agent_host_control("worker-crash");
        let mut node = VosNode::new();
        let handle = control.handle_for_test();
        node.attach_local_agent_host(control).unwrap();
        assert_eq!(
            handle.crash_worker_for_test(),
            Err(crate::agent::host::AgentHostError::WorkerStopped)
        );
        assert!(matches!(
            node.collect_checked(),
            Err(crate::agent::host::AgentHostError::WorkerPanicked)
        ));
    }

    #[test]
    fn agent_host_crash_stops_a_node_even_while_a_legacy_worker_is_live() {
        let (control, _remove) = empty_agent_host_control("mixed-worker-crash");
        let mut node = VosNode::new();
        let handle = control.handle_for_test();
        node.attach_local_agent_host(control).unwrap();
        let shutdown = node.shutdown_handle();
        let worker_shutdown = shutdown.clone();
        node.agents.push(AgentHandle {
            join: Some(thread::spawn(move || {
                while !worker_shutdown.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                AgentResult {
                    id: ServiceId(0x44),
                    panics: 0,
                    error: None,
                }
            })),
        });

        assert_eq!(
            handle.crash_worker_for_test(),
            Err(crate::agent::host::AgentHostError::WorkerStopped)
        );
        node.run_forever();
        assert!(
            shutdown.load(Ordering::Acquire),
            "Agent-host failure must fan out before a live legacy worker can mask it"
        );
        assert!(matches!(
            node.collect_checked(),
            Err(crate::agent::host::AgentHostError::WorkerPanicked)
        ));
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn lifecycle_tick_observes_shutdown_before_periodic_reconciliation() {
        let mut node = VosNode::new();
        assert!(node.drive_clean_agent_owner());
        node.shutdown_handle().store(true, Ordering::Release);
        assert!(!node.drive_clean_agent_owner());
        assert!(node.clean_agent_owner.is_none());
    }

    #[test]
    fn raw_shutdown_is_observed_before_draining_a_busy_outbox() {
        let (control, _remove) = empty_agent_host_control("busy-shutdown");
        let mut node = VosNode::new();
        node.attach_local_agent_host(control).unwrap();
        for _ in 0..256 {
            node.outbox_tx
                .send(Envelope {
                    from: ServiceId(1),
                    to: ServiceId(2),
                    payload: Vec::new(),
                    authenticated_source_peer: None,
                    destination_peer: None,
                })
                .unwrap();
        }
        let mut ticks = 0;
        node.run_forever_with(|node| {
            ticks += 1;
            node.shutdown_handle().store(true, Ordering::Release);
        });
        assert_eq!(
            ticks, 1,
            "shutdown must be checked before consuming another queued envelope"
        );
        node.collect_checked().unwrap();
    }

    #[test]
    fn run_until_idle_fans_out_an_agent_host_crash_without_waiting_for_threshold() {
        let (control, _remove) = empty_agent_host_control("idle-worker-crash");
        let mut node = VosNode::new();
        let handle = control.handle_for_test();
        node.attach_local_agent_host(control).unwrap();
        assert_eq!(
            handle.crash_worker_for_test(),
            Err(crate::agent::host::AgentHostError::WorkerStopped)
        );
        let started = Instant::now();
        node.run_until_idle(Duration::from_secs(60));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(node.shutdown_handle().load(Ordering::Acquire));
        assert!(matches!(
            node.collect_checked(),
            Err(crate::agent::host::AgentHostError::WorkerPanicked)
        ));
    }

    #[test]
    fn active_agent_host_work_defers_the_complete_node_idle_window() {
        let (control, _remove) = empty_agent_host_control("active-idle-window");
        let mut node = VosNode::new();
        let handle = control.handle_for_test();
        node.attach_local_agent_host(control).unwrap();
        let (active_tx, active_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let worker_handle = handle.clone();
        let request =
            thread::spawn(move || worker_handle.block_worker_for_test(active_tx, release_rx));
        active_rx.recv().unwrap();

        let threshold = Duration::from_millis(100);
        let held = Duration::from_millis(150);
        let (release_go, release_go_rx) = mpsc::sync_channel(0);
        let releaser = thread::spawn(move || {
            release_go_rx.recv().unwrap();
            thread::sleep(held);
            release_tx.send(()).unwrap();
        });
        let started = Instant::now();
        release_go.send(()).unwrap();
        node.run_until_idle(threshold);
        assert!(
            started.elapsed() >= held + threshold - Duration::from_millis(10),
            "idle shutdown must wait for active Agent work and then a fresh threshold"
        );
        releaser.join().unwrap();
        assert_eq!(request.join().unwrap(), Ok(()));
        node.collect_checked().unwrap();
    }

    #[test]
    fn service_native_extension_dispatch_is_capability_gated_and_context_bound() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4400);
        let target = ServiceId::new(0, 0x4401);
        let invocation = crate::service::InvocationId([0x42; 32]);
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("Substrate".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);

        let denied = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: ASK_TIMEOUT,
            caps: Vec::new(),
            invoke_routes: routes.clone(),
            agent_info: infos.clone(),
        };
        assert_eq!(
            denied.invoke("substrate", invocation, b"request"),
            Err(crate::actors::run::STATUS_FORBIDDEN),
        );
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        let worker = thread::spawn(move || {
            let request = rx.recv().unwrap();
            assert_eq!(request.caller, crate::Caller::Actor(caller));
            assert_eq!(request.space_role, Some(crate::SpaceRole::Member.as_u8()));
            assert_eq!(request.actor_local_role, None);
            assert_eq!(request.invocation_id, Some(invocation));
            assert!(
                request
                    .native_call
                    .as_ref()
                    .expect("service bridge installs call control")
                    .try_start()
            );
            assert_eq!(request.chain, vec![0x3300, caller.0]);
            assert_eq!(request.msg, b"request");
            request.reply.send(encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                b"reply",
            ));
        });
        let allowed = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: ASK_TIMEOUT,
            caps: vec![crate::IntraCap::parse("substrate:member").unwrap()],
            invoke_routes: routes,
            agent_info: infos,
        };
        {
            let _chain = ServiceNativeExtensionChainGuard::stamp(&[0x3300], caller);
            assert_eq!(
                allowed.invoke("substrate", invocation, b"request"),
                Ok(b"reply".to_vec()),
            );
        }
        assert_eq!(
            current_service_native_extension_chain(caller),
            vec![caller.0],
            "the dispatch-local lineage must be cleared after the request",
        );
        worker.join().unwrap();
    }

    #[test]
    fn service_native_extension_timeout_cancels_only_queued_work() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4410);
        let target = ServiceId::new(0, 0x4411);
        let invocation = crate::service::InvocationId([0x52; 32]);
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("substrate".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);
        let invoker = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: Duration::from_millis(5),
            caps: vec![crate::IntraCap::parse("substrate:member").unwrap()],
            invoke_routes: routes,
            agent_info: infos,
        };

        assert_eq!(
            invoker.invoke("substrate", invocation, b"queued"),
            Err(crate::actors::run::STATUS_PANICKED),
        );
        let request = rx.recv().expect("canceled request remains queued");
        assert!(
            !request
                .native_call
                .as_ref()
                .expect("service bridge installs call control")
                .try_start()
        );
    }

    #[test]
    fn service_native_extension_waits_for_work_the_worker_claimed() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4420);
        let target = ServiceId::new(0, 0x4421);
        let invocation = crate::service::InvocationId([0x62; 32]);
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("substrate".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);
        let (ready_tx, ready_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let request = rx.recv().unwrap();
            assert!(request.native_call.as_ref().unwrap().try_start());
            thread::sleep(Duration::from_millis(300));
            request.reply.send(encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                b"durable",
            ));
        });
        ready_rx.recv().unwrap();
        let invoker = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: Duration::from_millis(250),
            caps: vec![crate::IntraCap::parse("substrate:member").unwrap()],
            invoke_routes: routes,
            agent_info: infos,
        };

        assert_eq!(
            invoker.invoke("substrate", invocation, b"running"),
            Ok(b"durable".to_vec()),
        );
        worker.join().unwrap();
    }

    #[test]
    fn service_native_extension_bridge_rejects_replicated_roots() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4430);
        let target = ServiceId::new(0, 0x4431);
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("substrate".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);
        let invoker = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Raft,
            timeout: ASK_TIMEOUT,
            caps: vec![crate::IntraCap::parse("substrate:member").unwrap()],
            invoke_routes: routes,
            agent_info: infos,
        };

        assert_eq!(
            invoker.invoke(
                "substrate",
                crate::service::InvocationId([0x72; 32]),
                b"request",
            ),
            Err(crate::actors::run::STATUS_FORBIDDEN),
        );
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn service_native_extension_dispatch_rejects_reentry_from_its_target() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4600);
        let target = ServiceId::new(0, 0x4601);
        let invocation = crate::service::InvocationId([0x44; 32]);
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("substrate".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);
        let invoker = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: ASK_TIMEOUT,
            caps: vec![crate::IntraCap::parse("substrate:member").unwrap()],
            invoke_routes: routes,
            agent_info: infos,
        };

        let _chain = ServiceNativeExtensionChainGuard::stamp(&[0x3200, target.0], caller);
        assert_eq!(
            invoker.invoke("substrate", invocation, b"request"),
            Err(crate::actors::run::STATUS_PANICKED),
        );
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn service_native_extension_dispatch_rejects_actor_and_ambiguous_names() {
        use crate::service::NativeExtensionInvoker as _;

        let caller = ServiceId::new(0, 0x4500);
        let invocation = crate::service::InvocationId([0x43; 32]);
        let cap = vec![crate::IntraCap::parse("substrate:member").unwrap()];
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let actor_infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            0x4501,
            AgentInfo {
                name: Some("substrate".into()),
                consistency: Some(Consistency::Local),
                network_reachable: false,
            },
        )])));
        let actor_only = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: ASK_TIMEOUT,
            caps: cap.clone(),
            invoke_routes: routes.clone(),
            agent_info: actor_infos,
        };
        assert_eq!(
            actor_only.invoke("substrate", invocation, b"request"),
            Err(crate::actors::run::STATUS_NOT_FOUND),
        );

        let ambiguous_infos: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([
            (
                0x4502,
                AgentInfo {
                    name: Some("substrate".into()),
                    consistency: None,
                    network_reachable: true,
                },
            ),
            (
                0x4503,
                AgentInfo {
                    name: Some("Substrate".into()),
                    consistency: None,
                    network_reachable: true,
                },
            ),
        ])));
        let ambiguous = ServiceNativeExtensionInvoker {
            caller,
            consistency: crate::service::ConsistencyMode::Local,
            timeout: ASK_TIMEOUT,
            caps: cap,
            invoke_routes: routes,
            agent_info: ambiguous_infos,
        };
        assert_eq!(
            ambiguous.invoke("substrate", invocation, b"request"),
            Err(crate::actors::run::STATUS_PANICKED),
        );
    }

    #[test]
    fn ingress_idempotency_identity_is_stable_and_protocol_scoped() {
        let target = crate::service::ActorId([3; 32]);
        let first = ingress_invocation_id(
            crate::service::SubjectId([1; 32]),
            target,
            "http",
            "request-7",
        );
        assert_eq!(
            first,
            ingress_invocation_id(
                crate::service::SubjectId([1; 32]),
                target,
                "http",
                "request-7",
            ),
        );
        assert_ne!(
            first,
            ingress_invocation_id(
                crate::service::SubjectId([2; 32]),
                target,
                "http",
                "request-7",
            ),
        );
        assert_ne!(
            first,
            ingress_invocation_id(
                crate::service::SubjectId([1; 32]),
                target,
                "http",
                "request-8",
            ),
        );
        assert_ne!(
            first,
            ingress_invocation_id(
                crate::service::SubjectId([1; 32]),
                target,
                "ssh",
                "request-7",
            ),
        );
        assert!(first.retains_idempotent_result());
        assert!(
            !crate::service::InvocationId::derive(b"vos/node/ordinary-ingress", b"request-7")
                .retains_idempotent_result(),
            "ordinary authentication and query invocations never consume the recovery budget",
        );
    }

    #[test]
    fn node_lifecycle_basic() {
        let mut node = VosNode::new();
        node.run();
        let results = node.collect();
        assert!(results.is_empty());
    }

    #[test]
    fn attested_service_reply_does_not_time_out_a_non_cancellable_commit() {
        let (tx, rx) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            tx.send(b"committed attestation".to_vec()).unwrap();
        });
        let expired = Instant::now()
            .checked_add(Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            receive_service_invocation_reply(&rx, true, expired).unwrap(),
            b"committed attestation",
        );
        sender.join().unwrap();

        let (_tx, rx) = mpsc::channel();
        assert!(matches!(
            receive_service_invocation_reply(&rx, false, Instant::now()),
            Err(crate::actors::client::ClientError::Unreachable)
        ));
    }

    #[test]
    fn ingress_handle_does_not_abandon_accepted_work_at_the_route_timeout() {
        use crate::Encode as _;

        let node = VosNode::new();
        let target = crate::service::ActorId([0x71; 32]);
        let route = ServiceId::new(0, 0x7272);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([0x73; 32]),
            root_service: crate::service::RootServiceId([0x74; 32]),
            deployment: crate::service::DeploymentId([0x75; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000, 1_000_000),
        };
        node.service_actor_routes.write().unwrap().insert(
            target,
            ActorRoute {
                route: route.0,
                service,
                consistency: crate::service::ConsistencyMode::Crdt,
                replication_id: None,
                is_role_authority: false,
                invoke_timeout: Duration::from_millis(1),
                authenticated_peer: None,
            },
        );
        let (tx, rx) = mpsc::channel();
        node.invoke_routes.lock().unwrap().insert(route.0, tx);
        let responder = std::thread::spawn(move || {
            let request = rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(25));
            assert!(request.reply.send(encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                b"recovered authorized reply",
            )));
        });
        let mut arguments = vec![crate::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&crate::value::Msg::new("member_only").encode());
        assert_eq!(
            node.ingress_handle()
                .invoke_actor(
                    crate::service::SubjectId([0x76; 32]),
                    target,
                    arguments,
                    false,
                )
                .unwrap(),
            b"recovered authorized reply",
        );
        responder.join().unwrap();
        assert!(node.collect().is_empty());
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn inventory_http_admission_verifies_combined_selector_signature_before_dispatch() {
        use crate::agent::sdk::authority::{
            AgentAuthorityBinding, AuthorityActorTarget, AuthorityIngressAuthentication,
            AuthorityIssuer, AuthorityProjectionQuery, AuthorityProjectionSelector,
        };
        use crate::agent::sdk::{
            ActorId, AgentId, CredentialId, DeploymentId, Hash, PrincipalId, ProducerId, ProgramId,
            SpaceId,
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let public = key.verifying_key().to_bytes();
        let authority = AuthorityActorTarget {
            space: SpaceId([0x31; 32]),
            system_agent: AgentId([0x32; 32]),
            system_runtime_deployment: DeploymentId([0x33; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x34; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x35; 32]),
                    actor: ActorId([0x36; 32]),
                    deployment: DeploymentId([0x37; 32]),
                    program: ProgramId([0x38; 32]),
                    producer: ProducerId::of_public_key(&public),
                },
                public_key: public,
                initial_epoch: 1,
            },
        };
        let mut query = AuthorityProjectionQuery {
            recovery: None,
            authority,
            credential: CredentialId::of_public_key(&public),
            nonce: Hash([0x39; 32]),
            selector: AuthorityProjectionSelector::Inventory {
                after: None,
                limit: 64,
                known_head: None,
            },
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public,
                signature: [1; 64],
            },
        };
        let node = VosNode::new();
        let handle = node.ingress_handle();
        assert_eq!(
            handle.query_clean_agent_inventory(query.clone()),
            Err(IngressAuthenticationError::Invalid)
        );
        let signature = key.sign(&query.signing_bytes()).to_bytes();
        if let AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: value, ..
        } = &mut query.authentication
        {
            *value = signature;
        }
        assert_eq!(
            handle.query_clean_agent_inventory(query.clone()),
            Err(IngressAuthenticationError::AuthorityUnavailable)
        );
        query.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 1,
            known_head: None,
        };
        assert_eq!(
            handle.query_clean_agent_inventory(query),
            Err(IngressAuthenticationError::Invalid)
        );
    }

    #[cfg(feature = "ssh-ingress")]
    #[test]
    fn ssh_ingress_attester_is_set_once_and_signs_only_the_exact_query() {
        use crate::agent::sdk::authority::{
            AgentAuthorityBinding, AuthorityActorTarget, AuthorityIngressAuthentication,
            AuthorityIssuer, AuthorityProjectionSelector,
        };
        use crate::agent::sdk::{
            ActorId, AgentId, DeploymentId, Hash, NodeId, PrincipalId, ProducerId, ProgramId,
            SpaceId,
        };
        use ed25519_dalek::{Signer as _, SigningKey};

        let credential_key = SigningKey::from_bytes(&[0x21; 32]);
        let credential_public_key = credential_key.verifying_key().to_bytes();
        let authority_key = SigningKey::from_bytes(&[0x22; 32]);
        let authority_public_key = authority_key.verifying_key().to_bytes();
        let authority = AuthorityActorTarget {
            space: SpaceId([0x31; 32]),
            system_agent: AgentId([0x32; 32]),
            system_runtime_deployment: DeploymentId([0x33; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x34; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x35; 32]),
                    actor: ActorId([0x36; 32]),
                    deployment: DeploymentId([0x37; 32]),
                    program: ProgramId([0x38; 32]),
                    producer: ProducerId::of_public_key(&authority_public_key),
                },
                public_key: authority_public_key,
                initial_epoch: 1,
            },
        };
        let node_key = SigningKey::from_bytes(&[0x41; 32]);
        let node_public_key = node_key.verifying_key();
        let node = NodeId([0x42; 32]);
        let nonce = Hash([0x43; 32]);
        let request_binding = Hash([0x44; 32]);
        let selector = AuthorityProjectionSelector::Actors {
            agent: AgentId([0x45; 32]),
            after: None,
            limit: 8,
        };

        let mut vos_node = VosNode::new();
        assert_eq!(
            vos_node.ingress_handle().attest_ssh_projection_query(
                authority,
                credential_public_key,
                nonce,
                selector,
                request_binding,
            ),
            Err(IngressNodeAttestationError::NotConfigured),
        );
        assert_eq!(
            vos_node.set_ingress_node_attester(NodeId::ZERO, |_| Some([1; 64])),
            Err(IngressNodeAttestationError::InvalidNode),
        );
        vos_node
            .set_ingress_node_attester(node, move |message| Some(node_key.sign(message).to_bytes()))
            .unwrap();
        assert_eq!(
            vos_node.set_ingress_node_attester(NodeId([0x46; 32]), |_| Some([1; 64])),
            Err(IngressNodeAttestationError::AlreadyConfigured),
        );

        let query = vos_node
            .ingress_handle()
            .attest_ssh_projection_query(
                authority,
                credential_public_key,
                nonce,
                selector,
                request_binding,
            )
            .unwrap();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            node: attesting_node,
            request_binding: signed_request_binding,
            signature,
            ..
        } = query.authentication
        else {
            panic!("SSH transport must use node attestation");
        };
        assert_eq!(attesting_node, node);
        assert_eq!(signed_request_binding, request_binding);
        node_public_key
            .verify_strict(
                &query.signing_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();

        let mut substituted_selector = query.clone();
        substituted_selector.selector = AuthorityProjectionSelector::Actors {
            agent: AgentId([0x45; 32]),
            after: Some(ActorId([0x47; 32])),
            limit: 8,
        };
        assert!(
            node_public_key
                .verify_strict(
                    &substituted_selector.signing_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .is_err(),
        );

        let mut substituted_binding = query;
        substituted_binding.authentication = AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key,
            node,
            request_binding: Hash([0x48; 32]),
            signature,
        };
        assert!(
            node_public_key
                .verify_strict(
                    &substituted_binding.signing_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .is_err(),
        );
        assert_eq!(
            vos_node.ingress_handle().attest_ssh_projection_query(
                authority,
                [0; 32],
                nonce,
                selector,
                request_binding,
            ),
            Err(IngressNodeAttestationError::InvalidCredential),
        );
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn redirected_attestation_redrives_the_exact_invocation_after_transport_loss() {
        use crate::actors::run::{STATUS_DONE, STATUS_FORBIDDEN, STATUS_PANICKED};

        let request = crate::service::RootTreeInvocation {
            invocation: crate::service::InvocationId([3; 32]),
            target: crate::service::ActorId([4; 32]),
            method: "prove".into(),
            arguments: b"private reference".to_vec(),
            proof_requested: true,
        };
        let ingress = crate::service::ServiceWire::encode(&request);
        let terminal = encode_invoke_envelope(STATUS_DONE, &[], b"committed proof");
        let mut remote_wires = Vec::new();
        let mut remote_prefixes = Vec::new();
        let mut local_wires = Vec::new();
        let mut backoffs = 0;

        let result = receive_service_attested_with_exact_redrive(
            &ingress,
            RaftRedirect {
                leader_prefix: 41,
                origin: crate::service::Origin::System,
                root_upgrade_request: false,
            },
            |redirect, wire| {
                remote_prefixes.push(redirect.leader_prefix);
                remote_wires.push(wire.to_vec());
                match remote_wires.len() {
                    1 => AttestedRedriveAttempt::Ambiguous,
                    2 => AttestedRedriveAttempt::Reply(Vec::new()),
                    3 => AttestedRedriveAttempt::Reply(encode_invoke_envelope(
                        STATUS_PANICKED,
                        &[],
                        &[],
                    )),
                    _ => AttestedRedriveAttempt::Reply(terminal.clone()),
                }
            },
            |wire| {
                local_wires.push(wire.to_vec());
                let envelope = match local_wires.len() {
                    1 => encode_service_raft_redirect(42, crate::service::Origin::System, false),
                    2 => encode_invoke_envelope(STATUS_FORBIDDEN, &[], &[]),
                    _ => encode_service_raft_redirect(43, crate::service::Origin::System, false),
                };
                AttestedRedriveAttempt::Reply(envelope)
            },
            || backoffs += 1,
        )
        .unwrap();

        assert_eq!(result, b"committed proof");
        assert_eq!(remote_prefixes, [41, 42, 42, 43]);
        assert_eq!(
            remote_wires,
            [
                ingress.clone(),
                ingress.clone(),
                ingress.clone(),
                ingress.clone(),
            ]
        );
        assert_eq!(local_wires, [ingress.clone(), ingress.clone(), ingress]);
        assert_eq!(backoffs, 3, "redirects and ambiguous cycles back off");
    }

    /// The extension-facing proof-blob CAS round trip: `EFFECT_BLOB_PUT`
    /// (`handle_blob_put`) stores under the store's own addressing
    /// (`proof_blob_hash`, i.e. `put_proof_blob` parity) and
    /// `EFFECT_BLOB_GET` (`handle_blob_get`) returns the same bytes for
    /// the returned hash.
    #[test]
    fn blob_put_round_trips_through_blob_get() {
        let store: ProofBlobStore = Arc::new(RwLock::new(HashMap::new()));
        #[cfg(feature = "network")]
        let net: SharedNetwork = Arc::new(Mutex::new(None));
        let blob_fetch = BlobFetchCtx {
            proof_blobs: &store,
            proof_blobs_dir: None,
            #[cfg(feature = "network")]
            shared_network: &net,
        };
        let bytes = b"per-segment proof bytes".to_vec();
        let reply = handle_blob_put(&bytes, &blob_fetch);
        assert_eq!(
            reply,
            proof_blob_hash(&bytes).to_vec(),
            "the put reply is the 32-byte content hash under the store's addressing"
        );
        // The get payload is `[hash:32][hint_prefix:u16 LE]`.
        let mut req = reply.clone();
        req.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            handle_blob_get(&req, &blob_fetch),
            bytes,
            "blob_get serves the bytes blob_put stored"
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn consistency_byte_roundtrips() {
        for c in [
            Consistency::Ephemeral,
            Consistency::Local,
            Consistency::Crdt,
            Consistency::Raft,
        ] {
            assert_eq!(Consistency::from_u8(c.as_u8()), Some(c));
        }
        assert_eq!(Consistency::from_u8(4), None);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn shareability_orders_confined_below_replicated() {
        assert!(Consistency::Ephemeral.shareability() < Consistency::Local.shareability());
        assert!(Consistency::Local.shareability() < Consistency::Crdt.shareability());
        // Crdt and Raft are both fully shared — rank-equal.
        assert_eq!(
            Consistency::Crdt.shareability(),
            Consistency::Raft.shareability()
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn seal_pins_exact_tier_forbidding_widen_and_lateral() {
        use Consistency::*;
        // No prior seal: the request passes through unchanged.
        assert_eq!(effective_after_seal(None, Crdt), Crdt);
        assert_eq!(effective_after_seal(None, Local), Local);
        // Sealed Local: a forged/merged row claiming Crdt or Raft is
        // pinned back to Local — the immutable-local guarantee.
        assert_eq!(effective_after_seal(Some(Local), Crdt), Local);
        assert_eq!(effective_after_seal(Some(Local), Raft), Local);
        // Sealed Local stays Local; narrowing to Ephemeral is allowed.
        assert_eq!(effective_after_seal(Some(Local), Local), Local);
        assert_eq!(effective_after_seal(Some(Local), Ephemeral), Ephemeral);
        // Deliberate narrowing of a shared agent is honoured.
        assert_eq!(effective_after_seal(Some(Crdt), Local), Local);
        assert_eq!(effective_after_seal(Some(Raft), Ephemeral), Ephemeral);
        // The `Crdt`<->`Raft` lateral is now PINNED to the sealed tier:
        // a forged catalog byte can't downgrade a Raft replica to merge-anyone
        // CRDT (or upgrade the reverse). Exact re-spawn still passes.
        assert_eq!(effective_after_seal(Some(Crdt), Raft), Crdt);
        assert_eq!(effective_after_seal(Some(Raft), Crdt), Raft);
        assert_eq!(effective_after_seal(Some(Raft), Raft), Raft);
        assert_eq!(effective_after_seal(Some(Crdt), Crdt), Crdt);
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn forged_registry_rows_are_rejected_at_replay() {
        // The cross-node consistency boundary, deterministically. A peer can
        // author a byte-consistent registry `CrdtEvent`, and an honest
        // node WILL merge it — `insert_node` only checks the CID, not
        // the author. The defense is at replay: `replay_dag_into_runtime`
        // feeds each merged op back through the actor as `Caller::System`
        // (the `#[msg(role)]` gate a no-op), where `authorize_op`
        // re-verifies the embedded signature.
        //
        // We hand-build a registry DAG exactly as a peer's sync would
        // deliver it — genesis `set_root`, then root-signed ops (the
        // positive controls) interleaved with forged ops signed by a
        // non-admin — inject it via the same `insert_node` path, then
        // cold-start the registry so the real replay runs. The
        // root-signed install must land; the forged install must not. This is the
        // end-to-end counterpart to the registry's
        // `forged_*_rejected_on_system_replay_path` unit tests, which
        // exercise only the actor struct.
        use crate::actors::codec::Encode;
        use crate::commit::{Blake2b, CrdtCommit};
        use crate::effect_log::{CrdtEvent, EffectLog};
        use crate::value::{Msg, TAG_DYNAMIC};
        use ed25519_dalek::{Signer, SigningKey};
        use merkle_crdt::DagNode;
        use std::collections::BTreeSet;

        let workspace = env!("CARGO_MANIFEST_DIR");
        let elf_path = format!("{workspace}/../vosx/blobs/space_registry.elf");
        let elf = std::fs::read(&elf_path).expect("canonical space-registry ELF is committed");
        let blob = vos_pvm_compiler::link_elf(&elf).expect("registry transpiles");

        // ── Identities ──────────────────────────────────────────────
        let root_key = SigningKey::from_bytes(&[7u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let peer_id_for = |pk: [u8; 32]| -> Vec<u8> {
            let mut id = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
            id.extend_from_slice(&pk);
            id
        };
        let root_peer = peer_id_for(root_key.verifying_key().to_bytes());
        let attacker_peer = peer_id_for(attacker_key.verifying_key().to_bytes());
        let replay_space_id = [0x12; 32];

        // auth blob = signer_peer_id || ed25519_sig(space-bound canonical).
        let auth_as =
            |key: &SigningKey, signer_peer: &[u8], op: &str, fields: &[&[u8]]| -> Vec<u8> {
                let canonical =
                    space_registry::registry_mutation_signed_bytes(&replay_space_id, op, fields);
                let sig = key.sign(&canonical).to_bytes();
                space_registry::pack_auth(signer_peer, &sig)
            };

        // A shared service program the installs pin to.
        let prog = "p";
        let hash = vec![7u8; 32];
        let rep = vec![9u8; 32];
        let publication = vec![8u8; 32];
        let consistency = Consistency::Crdt.as_u8();

        // ── Registry op messages (bare `[TAG_DYNAMIC][Msg]`, the shape
        //    `EffectLog.msg` records — replay re-adds the caller prefix) ─
        let dyn_payload = |m: Msg| -> Vec<u8> {
            let mut p = vec![TAG_DYNAMIC];
            p.extend_from_slice(&m.encode());
            p
        };
        let install_msg = |key: &SigningKey, signer: &[u8], inst: &str| {
            let installation = vec![if inst == "good" { 10 } else { 11 }; 32];
            dyn_payload(
                Msg::new("install_service_actor")
                    .with("instance_name", inst.to_string())
                    .with("program_name", prog.to_string())
                    .with("program_hash", hash.clone())
                    .with("program_publication_id", publication.clone())
                    .with("installation_id", installation.clone())
                    .with("replication_id", rep.clone())
                    .with("consistency", consistency as u64)
                    .with("network_reachable", false)
                    .with("sync_role", crate::registry::SyncFloor::Member as u64)
                    .with(
                        "auth",
                        auth_as(
                            key,
                            signer,
                            "install_service_actor",
                            &[
                                inst.as_bytes(),
                                prog.as_bytes(),
                                &hash,
                                &publication,
                                &installation,
                                &rep,
                                &[consistency],
                                &[0u8], // network_reachable = false
                                &[crate::registry::SyncFloor::Member as u8], // sync_role
                            ],
                        ),
                    ),
            )
        };

        let set_root = dyn_payload(
            Msg::new("set_root")
                .with("root", root_peer.clone())
                .with("schema_version", crate::registry::REGISTRY_SCHEMA_VERSION)
                .with(
                    "schema_hash",
                    crate::registry::REGISTRY_SCHEMA_HASH.to_vec(),
                ),
        );
        let set_space_id =
            dyn_payload(Msg::new("set_space_id").with("space_id", replay_space_id.to_vec()));
        let publish = dyn_payload(
            Msg::new("publish_service_program")
                .with("name", prog.to_string())
                .with("hash", hash.clone())
                .with("crdt", true)
                .with("publication_id", publication.clone())
                .with("expected_publication_id", Vec::<u8>::new())
                .with("expected_hash", Vec::<u8>::new())
                .with(
                    "auth",
                    auth_as(
                        &root_key,
                        &root_peer,
                        "publish_service_program",
                        &[prog.as_bytes(), &hash, &[1u8], &publication, &[], &[]],
                    ),
                ),
        );
        let ops = [
            set_root,
            set_space_id,
            publish,
            install_msg(&root_key, &root_peer, "good"), // valid install
            install_msg(&attacker_key, &attacker_peer, "evil"), // forged install
        ];

        // ── Pre-seed the registry's redb with the DAG, exactly as a
        //    peer's sync would: `insert_node` + `compact_roots`, no
        //    committed state — so cold start replays the whole chain. ──
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir =
            std::env::temp_dir().join(format!("vos_forged_row_{}_{}", std::process::id(), stamp));
        let agents_dir = data_dir.join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        // db_path(ServiceId::REGISTRY) = {data_dir}/agents/{id.0:08x}.redb.
        let redb_path = agents_dir.join(format!("{:08x}.redb", ServiceId::REGISTRY.0));

        {
            let origin = [0x11u8; 32]; // a remote replica's origin
            let mut db = CrdtCommit::open(&redb_path, origin).unwrap();
            let mut prev: Option<merkle_crdt::Cid<Blake2b>> = None;
            for (seq, msg) in ops.into_iter().enumerate() {
                let event = CrdtEvent::new(origin, seq as u64, EffectLog::for_msg(msg));
                let children: BTreeSet<merkle_crdt::Cid<Blake2b>> = prev.into_iter().collect();
                let dag_node: DagNode<Blake2b, CrdtEvent> = DagNode::new(event, children);
                let cid = dag_node.cid();
                assert!(
                    db.insert_node(&cid.0, &dag_node.to_bytes()).unwrap(),
                    "node {seq} is new",
                );
                prev = Some(cid);
            }
            db.compact_roots().unwrap();
        } // drop releases the redb lock before the agent reopens it

        // ── Cold-start the registry over the seeded DAG ─────────────
        let mut node = VosNode::new();
        node.register_at_id(
            AgentConfig::new(blob)
                .with_consistency(Consistency::Crdt)
                .with_replication_id([0x11u8; 32])
                .persist(&data_dir),
            ServiceId::REGISTRY,
        );

        // Query via raw invoke (the typed `SpaceRegistryRef` can't be
        // used here — the dev-dep registry links a different vos build
        // than the crate under test, so `&node` doesn't satisfy its
        // `Invoker` bound). `peer_role` returns a `u8` (decodes as a
        // `Value`); for `agent` we compare the reply against a
        // known-`None` baseline rather than decoding `Option<AgentRow>`.
        let invoke = |m: Msg| -> Vec<u8> {
            let mut p = vec![TAG_DYNAMIC];
            p.extend_from_slice(&m.encode());
            node.invoke(ServiceId::REGISTRY, p).expect("registry reply")
        };
        let agent_reply =
            |inst: &str| invoke(Msg::new("service_actor").with("instance_name", inst.to_string()));
        let none_reply = agent_reply("does-not-exist"); // canonical `None` for this type

        // Positive controls: the root-signed ops survived replay —
        // proves the inject + replay pipeline is genuinely live.
        assert_ne!(
            agent_reply("good"),
            none_reply,
            "root-signed install must materialize an AgentRow on replay",
        );

        // The headline: forged ops were refused by authorize_op on the
        // System replay path, so neither row ever materializes.
        assert_eq!(
            agent_reply("evil"),
            none_reply,
            "forged install must be rejected at replay",
        );

        node.shutdown();
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn run_forever_with_idle_hook_gets_mut_node_and_can_invoke() {
        // A stand-in long-running agent: without one, the
        // all-agents-exited early-exit breaks the loop before the
        // idle hook ever fires.
        let mut node = VosNode::new();
        let stop = Arc::new(AtomicBool::new(false));
        let agent_stop = stop.clone();
        node.agents.push(AgentHandle {
            join: Some(thread::spawn(move || {
                while !agent_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(5));
                }
                AgentResult {
                    id: ServiceId(1),
                    panics: 0,
                    error: None,
                }
            })),
        });

        // The hook registers a responder on its first tick (the
        // &mut access registration needs), then synchronously
        // invokes it on later ticks — the same shape an embedder's
        // spawn-reconcile uses (register_at_id + registry query).
        let mut responder: Option<ServiceId> = None;
        let mut echoed: Option<Vec<u8>> = None;
        node.run_forever_with(|n| match responder {
            None => responder = Some(n.install_invoke_responder(|msg| msg)),
            Some(id) => {
                if echoed.is_none() {
                    echoed = n.invoke(id, b"ping".to_vec());
                }
                if echoed.is_some() {
                    n.shutdown();
                }
            }
        });
        stop.store(true, Ordering::Relaxed);
        assert_eq!(echoed.as_deref(), Some(&b"ping"[..]));
    }

    #[test]
    fn has_agent_tracks_registered_ids() {
        let node = VosNode::new();
        let id = ServiceId::new(0, 0x0123);
        assert!(!node.has_agent(id));
        node.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: Some("late".into()),
                consistency: None,
                network_reachable: false,
            },
        );
        assert!(node.has_agent(id));
    }

    #[test]
    fn relay_caller_guard_is_thread_scoped_and_clears() {
        use crate::actors::{Caller, SpaceRole};
        // No dispatch in flight on this thread → no relay caller.
        assert!(current_relay_caller().is_none());

        let pc = PropagatedCaller {
            caller: Caller::Peer(vec![0xaa, 0xbb]),
            space_role: Some(SpaceRole::Developer.as_u8()),
        };
        {
            let _g = RelayCallerGuard::stamp(pc.clone());
            // invoke_fn reads the slot on the SAME thread the sidecar
            // stamped it on — exactly the sidecar → handler →
            // ask_raw → invoke_fn chain.
            let seen = current_relay_caller().expect("stamped caller visible same-thread");
            assert_eq!(seen.caller, pc.caller);
            assert_eq!(seen.space_role, pc.space_role);

            // A DIFFERENT thread must not see this thread's caller —
            // the run()/tokio threads stay isolated, so a concurrent
            // self-originated call relays as None (→ Unauthenticated),
            // never another caller's identity.
            let other = std::thread::spawn(current_relay_caller);
            assert!(other.join().unwrap().is_none());
        }
        // Guard dropped → slot cleared; the next dispatch on this
        // thread can't inherit a stale caller.
        assert!(current_relay_caller().is_none());
    }

    #[test]
    fn relay_resolves_target_names_through_the_reverse_map() {
        // R3 — the relay path resolves *any* installed actor's name
        // from the same reverse map the libp2p gate uses, superseding
        // the old registry-only `relay_target_name`. The registry seeds
        // itself…
        let node = VosNode::new();
        node.record_agent_name(ServiceId::REGISTRY, None);
        node.record_agent_name(ServiceId::new(0, 0x0444), Some("workspace".into()));

        // Registry resolves (and still does under a node prefix — low
        // 16 bits zero).
        assert_eq!(
            node.agent_name_for(ServiceId::REGISTRY.0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
        assert_eq!(
            node.agent_name_for(ServiceId::new(0xBEEF, 0).0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
        // …and so does a non-registry installed agent — the cap for it
        // now binds instead of silently vanishing.
        assert_eq!(node.agent_name_for(0x0444).as_deref(), Some("workspace"));
        // An unregistered id stays unresolved → matches only `*` caps.
        assert_eq!(node.agent_name_for(0x0007), None);
    }

    #[test]
    fn resolve_relay_caller_intersection_matrix() {
        use crate::actors::{Caller, IntraCap, SpaceRole};

        let admin_cap = [IntraCap::parse("space-registry:admin").unwrap()];
        let dev_cap = [IntraCap::parse("space-registry:developer").unwrap()];

        let peer = |b: &[u8]| Caller::Peer(b.to_vec());
        let pc = |c: Caller, sr: Option<SpaceRole>| PropagatedCaller {
            caller: c,
            space_role: sr.map(|r| r.as_u8()),
        };

        // 1. SECURITY CORE: no cap declared for the target → the relay
        //    has no authority → Unauthenticated (role-gated handlers
        //    refuse). Holds even for an admin caller.
        let p_admin = pc(peer(&[1]), Some(SpaceRole::Admin));
        assert_eq!(
            resolve_relay_caller(Some(&p_admin), &[], Some("space-registry"), None),
            (Caller::Unauthenticated, None),
            "empty caps deny every role-gated relay",
        );
        // A cap for a *different* actor doesn't apply to this target.
        assert_eq!(
            resolve_relay_caller(Some(&p_admin), &admin_cap, Some("workspace"), None),
            (Caller::Unauthenticated, None),
        );

        // 2. Peer admin + admin cap → full admin relayed (transparent,
        //    identity preserved).
        let (c, sr) =
            resolve_relay_caller(Some(&p_admin), &admin_cap, Some("space-registry"), None);
        assert_eq!(c, peer(&[1]));
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));

        // 3. Peer member + admin cap → bounded by the *caller's* own
        //    role (min(Member, Admin) = Member): no amplification.
        let p_member = pc(peer(&[2]), Some(SpaceRole::Member));
        let (c, sr) =
            resolve_relay_caller(Some(&p_member), &admin_cap, Some("space-registry"), None);
        assert_eq!(c, peer(&[2]));
        assert_eq!(sr, Some(SpaceRole::Member.as_u8()));

        // 4. Peer admin but a lower cap ceiling → bounded DOWN by the
        //    cap (min(Admin, Developer) = Developer).
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &dev_cap, Some("space-registry"), None);
        assert_eq!(
            sr,
            Some(SpaceRole::Developer.as_u8()),
            "ceiling bounds an over-privileged caller",
        );

        // 5. No propagated caller (run()-thread / boot) → Unauthenticated
        //    even with a cap.
        assert_eq!(
            resolve_relay_caller(None, &admin_cap, Some("space-registry"), None),
            (Caller::Unauthenticated, None),
        );

        // 6. Unauthenticated incoming → nothing to relay.
        let p_unauth = pc(Caller::Unauthenticated, None);
        assert_eq!(
            resolve_relay_caller(Some(&p_unauth), &admin_cap, Some("space-registry"), None,),
            (Caller::Unauthenticated, None),
        );

        // 7. Internal origin kind grants nothing. An explicitly carried role
        //    is still capped and relayed anonymously.
        for internal in [Caller::System, Caller::Actor(ServiceId(9))] {
            let p_internal = pc(internal.clone(), None);
            assert_eq!(
                resolve_relay_caller(Some(&p_internal), &dev_cap, Some("space-registry"), None,),
                (Caller::Unauthenticated, None),
            );
            let p_internal = pc(internal, Some(SpaceRole::Admin));
            let (c, sr) =
                resolve_relay_caller(Some(&p_internal), &dev_cap, Some("space-registry"), None);
            assert_eq!(c, Caller::Unauthenticated);
            assert_eq!(
                sr,
                Some(SpaceRole::Developer.as_u8()),
                "explicit Admin role is capped to the extension ceiling"
            );
        }

        // 8. Wildcard-role cap ("space-registry:*") → uncapped: a peer
        //    admin keeps admin.
        let any_role = [IntraCap::parse("space-registry:*").unwrap()];
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &any_role, Some("space-registry"), None);
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));

        // 9. Wildcard-actor cap ("*:member") applies to an unresolved
        //    target and caps the admin caller to member.
        let any_actor = [IntraCap::parse("*:member").unwrap()];
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &any_actor, None, None);
        assert_eq!(sr, Some(SpaceRole::Member.as_u8()));

        // 10. Full wildcard ("*:*") — any role on any actor — uncaps a
        //     peer admin on both a named and an unresolved target.
        let full = [IntraCap::parse("*:*").unwrap()];
        let (c, sr) = resolve_relay_caller(Some(&p_admin), &full, Some("space-registry"), None);
        assert_eq!(c, peer(&[1]));
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &full, None, None);
        assert_eq!(
            sr,
            Some(SpaceRole::Admin.as_u8()),
            "full wildcard matches unresolved targets too"
        );
    }

    #[test]
    fn actor_principal_requires_a_matching_cap_and_never_amplifies_a_peer() {
        use crate::actors::{Caller, IntraCap, SpaceRole};

        let actor = ServiceId(77);
        let cap = [IntraCap::parse("substrate:member").unwrap()];
        assert_eq!(
            resolve_relay_caller(None, &cap, Some("substrate"), Some(actor)),
            (Caller::Actor(actor), Some(SpaceRole::Member.as_u8())),
        );
        assert_eq!(
            resolve_relay_caller(None, &[], Some("substrate"), Some(actor)),
            (Caller::Unauthenticated, None),
        );

        let anonymous = PropagatedCaller {
            caller: Caller::Unauthenticated,
            space_role: None,
        };
        assert_eq!(
            resolve_relay_caller(Some(&anonymous), &cap, Some("substrate"), Some(actor)),
            (Caller::Unauthenticated, None),
            "an untrusted caller cannot borrow the actor's autonomous capability",
        );

        let member = crate::service::SubjectId([9; 32]);
        let authenticated = PropagatedCaller {
            caller: Caller::Member(member),
            space_role: Some(SpaceRole::Developer.as_u8()),
        };
        assert_eq!(
            resolve_relay_caller(Some(&authenticated), &cap, Some("substrate"), Some(actor),),
            (Caller::Member(member), Some(SpaceRole::Member.as_u8())),
            "credential-backed identity remains caller-bound while the cap lowers its role",
        );
    }

    #[test]
    fn extension_config_carries_declared_caps() {
        use crate::actors::IntraCap;
        let caps = || vec![IntraCap::parse("space-registry:admin").unwrap()];

        let cfg = ExtensionConfig::new("x.so").with_intra_caps(caps());
        assert_eq!(cfg.intra_caps.len(), 1);
        assert!(ExtensionConfig::new("x.so").intra_caps.is_empty());
    }

    #[test]
    fn extension_receives_authenticated_invocation_context() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-extension first");
            return;
        }

        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("invocation_context").encode());

        let mut node = VosNode::new();
        let id = ServiceId(0x00ff_1010);
        node.register_extension_at_id(ExtensionConfig::new(echo_path), id);

        let system_reply = node
            .invoke(id, payload.clone())
            .expect("system invoke reply");
        let system_value: Value = crate::Decode::decode(&system_reply);
        let expected_system = format!("system|{}|set|none", id.0);
        assert_eq!(system_value.as_str(), Some(expected_system.as_str()));

        let invoke_tx = node
            .invoke_routes
            .lock()
            .unwrap()
            .get(&id.0)
            .cloned()
            .expect("extension invoke route");
        let (reply_tx, reply_rx) = mpsc::channel();
        invoke_tx
            .send(InvokeRequest {
                caller: crate::actors::Caller::Peer(vec![1, 2, 3]),
                space_role: Some(crate::actors::SpaceRole::Member.as_u8()),
                actor_local_role: None,
                #[cfg(all(feature = "network", feature = "storage"))]
                delegated_origin: None,
                role_authority_request: false,
                root_upgrade_request: false,
                invocation_id: None,
                native_call: None,
                msg: payload,
                reply: ReplyChannel::Sync(reply_tx),
                chain: Vec::new(),
            })
            .expect("send authenticated invoke");
        let envelope = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("authenticated invoke reply");
        let peer_reply = unwrap_invoke_envelope(&envelope).expect("successful invoke envelope");
        let peer_value: Value = crate::Decode::decode(&peer_reply);
        let expected_peer = format!("peer:[1, 2, 3]|{}|set|member", id.0);
        assert_eq!(peer_value.as_str(), Some(expected_peer.as_str()));

        node.shutdown();
        let results = node.collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].error, None);
    }

    #[test]
    #[cfg(feature = "storage")]
    fn named_extension_state_paths_are_stable_isolated_and_traversal_safe() {
        let data_dir = std::env::temp_dir().join(format!(
            "vos_extension_path_{}_{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_dir_all(&data_dir);

        let first = ExtensionConfig::new("libshared.so")
            .with_name("../../first")
            .persist(&data_dir)
            .db_path()
            .unwrap()
            .unwrap();
        let first_again = ExtensionConfig::new("libother.so")
            .with_name("../../first")
            .persist(&data_dir)
            .db_path()
            .unwrap()
            .unwrap();
        let second = ExtensionConfig::new("libshared.so")
            .with_name("second")
            .persist(&data_dir)
            .db_path()
            .unwrap()
            .unwrap();

        assert_eq!(first, first_again);
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(data_dir.join("extensions").as_path()));
        let filename = first.file_name().unwrap().to_str().unwrap();
        assert!(filename.starts_with("instance-"));
        assert!(filename.ends_with(".redb"));
        assert!(!filename.contains(".."));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "storage")]
    fn configured_extension_persistence_is_fail_closed() {
        let data_dir =
            std::env::temp_dir().join(format!("vos_extension_storage_file_{}", std::process::id()));
        let _ = std::fs::remove_file(&data_dir);
        let _ = std::fs::remove_dir_all(&data_dir);
        std::fs::write(&data_dir, b"not a directory").unwrap();

        let config = ExtensionConfig::new("libshared.so")
            .with_name("substrate")
            .persist(&data_dir);
        let error = build_extension_strategy(&config)
            .err()
            .expect("configured persistence failure must abort startup");
        assert!(error.contains("derive extension state path"));

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if echo_path.exists() {
            let mut node = VosNode::new();
            let id = ServiceId(0x00ff_1001);
            let error = node
                .try_register_extension_at_id(
                    ExtensionConfig::new(echo_path).persist(&data_dir),
                    id,
                )
                .expect_err("worker startup must report persistence setup failure");
            assert!(error.contains("derive extension state path"));
            assert!(!node.has_agent(id));
            assert!(!node.routes.contains_key(&id.0));
            assert!(!node.invoke_routes.lock().unwrap().contains_key(&id.0));
            assert!(!node.agent_shutdown.lock().unwrap().contains_key(&id.0));
        }

        std::fs::remove_file(&data_dir).unwrap();
    }

    #[test]
    fn failed_extension_load_is_reported_before_publication() {
        let mut node = VosNode::new();
        let id = ServiceId(0x00ff_1002);
        let missing = std::env::temp_dir().join(format!(
            "vos_missing_extension_{}_{}.so",
            std::process::id(),
            id.0
        ));
        let error = node
            .try_register_extension_at_id(ExtensionConfig::new(missing), id)
            .expect_err("a missing plugin must fail registration");
        assert!(error.contains("failed to load extension plugin"));
        assert!(!node.has_agent(id));
        assert!(!node.routes.contains_key(&id.0));
        assert!(!node.invoke_routes.lock().unwrap().contains_key(&id.0));
        assert!(!node.agent_shutdown.lock().unwrap().contains_key(&id.0));
    }

    // ── unwrap_invoke_envelope contract ─────────────────────────
    //
    // Locks in what b112aa6 doc-corrected: STATUS_DONE and
    // STATUS_YIELDED both surface their reply bytes; everything
    // else (PANICKED, NOT_FOUND, short envelopes, malformed
    // state_len) collapses to None so worker/host callers see
    // "no reply" rather than partial garbage.

    fn make_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
        // Mirrors `encode_invoke_envelope` exactly so we're not
        // testing the encoder against itself — keeps the test
        // honest if `encode_invoke_envelope` regresses.
        let mut v = Vec::with_capacity(5 + state.len() + reply.len());
        v.push(status);
        v.extend_from_slice(&(state.len() as u32).to_le_bytes());
        v.extend_from_slice(state);
        v.extend_from_slice(reply);
        v
    }

    #[test]
    fn unwrap_envelope_done_with_reply_yields_reply() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"some-state", b"the-reply");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"the-reply"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_done_with_empty_reply_yields_empty() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"state-only", b"");
        // Empty reply is meaningful: handler returned `()`.
        // Caller distinguishes `Some(empty)` (returned unit) from
        // `None` (envelope unusable).
        let r = unwrap_invoke_envelope(&env).expect("done envelope decodes");
        assert!(r.is_empty(), "empty-reply envelope must yield Some(empty)");
    }

    #[test]
    fn unwrap_envelope_yielded_surfaces_reply() {
        // YIELDED carries a post-dispatch state + the partial
        // reply so far. Host callers (worker) just want the
        // bytes; the YIELDED-vs-DONE distinction is for
        // `decode_invoke_envelope` on the runtime side.
        use crate::actors::run::STATUS_YIELDED;
        let env = make_envelope(STATUS_YIELDED, b"yielded-state", b"partial");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"partial"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_panicked_yields_none() {
        // HTTP ingress distinguishes panic → 502 from
        // "() return" → 200 null. That hinges on PANICKED
        // collapsing to None here.
        let env = make_envelope(crate::STATUS_PANICKED, b"", b"would-be-reply");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_not_found_yields_none() {
        let env = make_envelope(crate::STATUS_NOT_FOUND, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_too_short_yields_none() {
        // < 5 bytes can't carry status + state_len, regardless
        // of what those bytes claim.
        assert_eq!(unwrap_invoke_envelope(&[]), None);
        assert_eq!(unwrap_invoke_envelope(&[0]), None);
        assert_eq!(unwrap_invoke_envelope(&[0, 0, 0, 0]), None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn forbidden_envelope_is_5_bytes_starting_with_status_forbidden() {
        // Wire-shape contract: vosx's `is_forbidden_envelope` peeks
        // for exactly this 5-byte pattern to surface
        // `ClientError::Forbidden`. If either the length or the
        // status byte drifts, the client-side detection silently
        // breaks and refusals collapse back to "transport failure"
        // again. Pin both.
        let env = forbidden_envelope();
        assert_eq!(env.len(), 5, "forbidden envelope must be exactly 5 bytes");
        assert_eq!(env[0], crate::STATUS_FORBIDDEN, "status byte mismatch");
        assert_eq!(&env[1..5], &[0, 0, 0, 0], "state_len must be zero");
    }

    #[test]
    fn unwrap_envelope_forbidden_yields_none() {
        // STATUS_FORBIDDEN belongs to the same failure family as
        // PANICKED/NOT_FOUND/OOG for `unwrap_invoke_envelope` —
        // there's no actor-produced reply to surface. Client-side
        // detection happens at a different layer (Invoker for
        // &VosNode), not here.
        let env = make_envelope(crate::STATUS_FORBIDDEN, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    // ── Tell-path forgery defense ─────────────────────────────
    //
    // The dispatch-prefix protocol is the host's mechanism for asserting
    // "this dispatch is from <Caller> under <InvocationId>"; the PVM strips
    // the leading 38-byte header and trusts it. If any path
    // sends inbox-sourced bytes to the runtime *without* the
    // host's wrap, an attacker can prepend their own forged
    // header — flipping trust_flag=1 turns Caller::System on
    // and bypasses every role check.
    //
    // These tests pin the two host-side wrap shapes (replay +
    // inbox) so a refactor that drops the wrap (or flips a
    // trust flag) fails fast instead of silently re-opening the
    // attack surface.

    #[test]
    fn wrap_with_unauthenticated_prefix_layout() {
        // Inbox / Tell dispatch path must use the safe-default
        // wrap: trust_flag=0 (Unauthenticated), no role bytes.
        // Bytes 0..38 are the fixed-shape header; the original
        // payload trails verbatim.
        let inner = b"some-msg-bytes";
        let invocation = crate::service::InvocationId::derive(b"test", b"inbox");
        let wrapped = wrap_with_unauthenticated_prefix(inner, invocation);
        assert_eq!(
            wrapped[0],
            crate::actors::lifecycle::TAG_DISPATCH_PREFIX,
            "header must start with TAG_DISPATCH_PREFIX",
        );
        assert_eq!(
            wrapped[1], 0,
            "trust_flag MUST be 0 (Unauthenticated) for inbox-sourced \
             payloads — an attacker controls the inner bytes, so \
             trust=1 would forge Caller::System",
        );
        assert_eq!(
            &wrapped[2..6],
            &[0u8; 4],
            "role flags / bytes are all zero in the safe-default wrap",
        );
        assert_eq!(
            &wrapped[6..38],
            invocation.as_bytes(),
            "dispatch prefix carries the stable invocation id",
        );
        assert_eq!(
            &wrapped[38..],
            &inner[..],
            "inner payload trails the header verbatim",
        );
    }

    #[test]
    fn replay_payload_carries_recorded_caller() {
        // Replay re-runs a committed log entry under the RECORDED
        // caller prefix, so the original gate decision reproduces:
        // refused stays refused and granted stays granted.
        let inner = b"logged-msg";
        let recorded: crate::effect_log::CallerPrefix = [0, 1, 3, 0, 0];
        let invocation = crate::service::InvocationId::derive(b"test", b"replay");
        let wrapped = encode_replay_payload(&recorded, invocation, inner);
        assert_eq!(wrapped[0], crate::actors::lifecycle::TAG_DISPATCH_PREFIX);
        assert_eq!(&wrapped[1..6], &recorded[..]);
        assert_eq!(&wrapped[6..38], invocation.as_bytes());
        assert_eq!(&wrapped[38..], &inner[..]);
    }

    #[test]
    fn inbox_wrap_neutralises_forged_caller_prefix() {
        // Attacker crafts a Tell payload that *itself* starts
        // with TAG_DISPATCH_PREFIX and a forged trust_flag=1
        // (System). After the host wraps it with the safe
        // default, the attacker's bytes start at offset 38 — the
        // PVM's dispatch_one only strips one prefix, so the
        // attacker's bytes go to the Msg decoder, NOT to a
        // second caller-set. dispatch_one is single-pass, so
        // confirming the wrap puts the attacker's prefix at
        // offset 38 is sufficient to prove the forgery is
        // neutralised.
        let forged: Vec<u8> = std::iter::once(crate::actors::lifecycle::TAG_DISPATCH_PREFIX)
            .chain([1, 0, 0, 0, 0])
            .chain([0; 32])
            .chain(b"would-be-admin-call".iter().copied())
            .collect();
        let wrapped = wrap_with_unauthenticated_prefix(&forged, crate::service::InvocationId::ZERO);
        // Host's prefix at 0..38, attacker's bytes start at 38.
        assert_eq!(wrapped[1], 0, "outer trust_flag must be 0");
        assert_eq!(
            wrapped[38],
            crate::actors::lifecycle::TAG_DISPATCH_PREFIX,
            "attacker's prefix byte is preserved inside as msg \
             content — dispatch_one is single-pass so this byte \
             gets treated as the first byte of the inner Msg, not \
             as another caller-prefix to strip",
        );
        // The forged trust_flag=1 byte sits at offset 39, where
        // it can only be decoded as part of a malformed Msg.
        assert_eq!(wrapped[39], 1);
    }

    #[test]
    fn unwrap_envelope_oversized_state_len_yields_none() {
        // state_len claims more bytes than the envelope holds —
        // a hostile or corrupt wire payload. Must collapse to
        // None rather than slicing out-of-bounds.
        use crate::actors::run::STATUS_DONE;
        let mut env = Vec::new();
        env.push(STATUS_DONE);
        env.extend_from_slice(&(999u32).to_le_bytes()); // claims 999B state
        env.extend_from_slice(b"only-3"); // but only 6 bytes follow
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn invoke_forward_check_detects_cycle() {
        // Self-invoke (target already in chain).
        let chain = [1u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B with B trying to call A.
        let chain = [1u32, 2u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B→C, fresh target D — allowed.
        let chain = [1u32, 2u32, 3u32];
        assert_eq!(check_invoke_forward(&chain, 4), InvokeForwardCheck::Allowed);
    }

    #[test]
    fn extension_route_rejects_a_self_cycle_before_queueing() {
        let extension_id = ServiceId(41);
        let routes = InvokeRoutes::default();
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(extension_id.0, tx);
        let mut request = extension_id.0.to_le_bytes().to_vec();
        request.extend_from_slice(b"ignored");

        let result = async_io::block_on(route_invoke(
            &routes,
            &RaftFwd::default(),
            extension_id,
            &[extension_id.0],
            crate::actors::Caller::Unauthenticated,
            None,
            None,
            &request,
        ));

        assert_eq!(result, Err(crate::actors::run::STATUS_PANICKED));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn extension_route_rejects_a_cycle_through_scoped_fallback() {
        let prefix = 0x0042;
        let first = ServiceId::new(prefix, 2);
        let extension_id = ServiceId::new(prefix, 3);
        let routes = InvokeRoutes::default();
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(first.0, tx);
        // Extensions commonly receive unscoped local IDs from name
        // resolution. Routing would fall this `2` back to `first`.
        let mut request = u32::from(first.local_id()).to_le_bytes().to_vec();
        request.extend_from_slice(b"ignored");

        let result = async_io::block_on(route_invoke(
            &routes,
            &RaftFwd::default(),
            extension_id,
            &[first.0, extension_id.0],
            crate::actors::Caller::Unauthenticated,
            None,
            None,
            &request,
        ));

        assert_eq!(result, Err(crate::actors::run::STATUS_PANICKED));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn extension_route_preserves_the_complete_invoke_chain() {
        let extension_id = ServiceId(42);
        let target = ServiceId(43);
        let routes = InvokeRoutes::default();
        let (tx, rx) = mpsc::channel();
        routes.lock().unwrap().insert(target.0, tx);
        let responder = std::thread::spawn(move || {
            let req = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("routed invoke");
            assert_eq!(req.chain, vec![7, extension_id.0]);
            assert_eq!(req.msg, b"request");
            assert!(req.reply.send(encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                b"reply",
            )));
        });
        let mut request = target.0.to_le_bytes().to_vec();
        request.extend_from_slice(b"request");

        let reply = async_io::block_on(route_invoke(
            &routes,
            &RaftFwd::default(),
            extension_id,
            &[7, extension_id.0],
            crate::actors::Caller::Unauthenticated,
            None,
            None,
            &request,
        ))
        .expect("extension route reply");

        assert_eq!(reply, b"reply");
        responder.join().unwrap();
    }

    #[test]
    fn send_reply_capped_passes_normal_payload() {
        let (tx, rx) = mpsc::channel();
        assert!(send_reply_capped(
            ReplyChannel::Sync(tx),
            vec![0u8; 100],
            ServiceId(1)
        ));
        let received = rx.recv().expect("received");
        assert_eq!(received.len(), 100);
    }

    #[test]
    fn service_admission_slots_are_node_owned_and_monotone() {
        let future = service_wall_timeslot().saturating_add(1_000);
        let clock = AtomicU64::new(future);
        let first = next_service_logical_timeslot(&clock);
        let second = next_service_logical_timeslot(&clock);
        assert_eq!(first, future);
        assert_eq!(second, future + 1);
    }

    #[test]
    fn service_admission_slots_restore_above_durable_high_water() {
        let committed = service_wall_timeslot().saturating_add(10_000);
        let clock = AtomicU64::new(1);
        restore_service_logical_timeslot(&clock, committed).unwrap();
        assert_eq!(next_service_logical_timeslot(&clock), committed + 1);
        assert_eq!(next_service_logical_timeslot(&clock), committed + 2);
        assert_eq!(
            restore_service_logical_timeslot(&clock, u64::MAX),
            Err(NodeRegistrationError::LogicalTimeslotExhausted)
        );
    }

    #[test]
    fn service_delivery_slot_is_allocated_after_authority_clock_progress() {
        let floor = service_wall_timeslot().saturating_add(10_000);
        let clock = AtomicU64::new(floor.saturating_add(1));
        let provisional = floor.saturating_add(1);

        // A same-node authority invocation consumes the provisional point in
        // the shared ordering before the destination proposes its delivery.
        let authority_slot = next_service_logical_timeslot(&clock);
        assert_eq!(authority_slot, provisional);
        let deadline = authority_slot.saturating_add(1);
        assert!(provisional < deadline, "the provisional claim is live");
        let delivery_slot = allocate_service_conformance_slot_after_barrier(&clock, floor)
            .expect("slot remains available");
        assert!(delivery_slot > authority_slot);
        assert!(
            delivery_slot >= deadline,
            "guest delivery must now classify this call as expired"
        );
    }

    #[test]
    fn production_slots_are_exact_consensus_observations_and_never_regress() {
        let clock = AtomicU64::new(100);
        assert_eq!(
            allocate_service_observed_slot_after_barrier(&clock, 120, Some(121)),
            Ok(121),
        );
        assert_eq!(clock.load(Ordering::Relaxed), 121);
        assert_eq!(
            allocate_service_observed_slot_after_barrier(&clock, 121, Some(121)),
            Ok(121),
            "several transitions may share one consensus service platform slot",
        );
        assert_eq!(
            allocate_service_observed_slot_after_barrier(&clock, 121, Some(120)),
            Err(NodeRegistrationError::LogicalTimeslotRegressed),
        );
        assert_eq!(
            clock.load(Ordering::Relaxed),
            121,
            "a stale provider observation cannot move the local floor backward",
        );
        assert!(!service_root_slot_failure_is_terminal(
            NodeRegistrationError::LogicalTimeslotUnavailable,
        ));
        assert!(!service_root_slot_failure_is_terminal(
            NodeRegistrationError::LogicalTimeslotRegressed,
        ));
        assert!(service_root_slot_failure_is_terminal(
            NodeRegistrationError::LogicalTimeslotExhausted,
        ));
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn service_crdt_sync_is_split_into_causal_frame_bounded_chunks() {
        use crate::service::ServiceWire;

        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([1; 32]),
            root_service: crate::service::RootServiceId([2; 32]),
            deployment: crate::service::DeploymentId([3; 32]),
            service_program: crate::service::ProgramId([4; 32]),
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000, 1_000_000),
        };
        let actor = crate::service::ActorId([5; 32]);
        let mut dependency = Vec::new();
        let mut nodes = Vec::new();
        for ordinal in 0..12u8 {
            let ingress = crate::service::CrdtIngress {
                service: service.clone(),
                invocation: crate::service::InvocationId([ordinal.saturating_add(10); 32]),
                logical_timeslot: u64::from(ordinal) + 1,
                target: actor,
                method: "append".into(),
                arguments: vec![ordinal; 768],
                origin: crate::service::Origin::Anonymous,
                authorization: crate::service::AuthorizationEvidence::Public,
                authorization_blob: None,
                imported_blobs: Vec::new(),
                proof_requested: false,
            };
            let change = crate::service::CrdtChange {
                id: crate::service::CrdtChange::derive_ingress_id(&ingress, &dependency),
                work_hash: ingress.commitment(),
                causal_dependencies: dependency.clone(),
                causal_height: u64::from(ordinal) + 1,
                operations: Vec::new(),
                workflow: vec![crate::service::WorkflowOperation::Ingress(ingress)],
                materializations: Vec::new(),
                awaited_reply: None,
                exported_blobs: Vec::new(),
            };
            let cid = change.cid();
            nodes.push(crate::service::CrdtSyncNode {
                receipt: crate::service::AccumulationReceipt {
                    service: service.clone(),
                    accepted_transition: change.receipt_commitment(),
                    reply_commitment: None,
                    outbox_commitment: None,
                    resulting_state_root: None,
                    resulting_crdt_heads: vec![cid],
                    sequence: change.causal_height,
                    checkpoint: 0,
                    consistency: crate::service::ConsistencyMode::Crdt,
                },
                change,
            });
            dependency = vec![cid];
        }
        nodes.sort_by_key(|node| node.change.cid());
        let envelope = crate::service::CrdtSyncEnvelope {
            service,
            advertised_heads: dependency,
            nodes,
            provided_blobs: Vec::new(),
        };
        let cap = 3_200;
        let (transfer, chunks) = service_crdt_sync_chunks(envelope, cap).unwrap();
        assert!(chunks.len() > 1, "the focused cap must force chunking");
        let chunks = Arc::new(chunks);
        let count = chunks.len() as u32;
        for (index, chunk) in chunks.iter().cloned().enumerate() {
            let wire = crate::service::RootTreeTransport::CrdtSyncChunk {
                transfer,
                chunk_index: index as u32,
                chunk_count: count,
                envelope: chunk,
            }
            .encode();
            assert!(wire.len() <= cap, "every transport delta is frame-bounded");
            crate::service::RootTreeTransport::decode(&wire).unwrap();
        }

        let peer_key = vec![0xA5];
        let selected_at = Instant::now();
        let mut peer = CrdtPeerProgress::default();
        service_crdt_select_latest_peer_transfer(&mut peer, transfer, &chunks);
        assert_eq!(peer.transfer, Some(transfer));
        assert!(Arc::ptr_eq(peer.chunks.as_ref().unwrap(), &chunks));

        let newer_frontier = crate::service::Hash([0xE1; 32]);
        let newer_transfer = crate::service::Hash([0xE2; 32]);
        let newer_chunks = vec![chunks.last().unwrap().clone()];
        let mut progress = CrdtSyncProgress {
            latest_frontier: crate::service::Hash([0xE0; 32]),
            latest_transfer: transfer,
            latest_chunks: chunks.clone(),
            peers: HashMap::from([(peer_key.clone(), peer)]),
            roster_seen: HashSet::from([peer_key.clone()]),
            roster_after_kind: 7,
            roster_after_key: vec![8],
            next_roster_page: Instant::now(),
            fanout_after: Some(peer_key.clone()),
        };
        progress.replace_latest(newer_frontier, newer_transfer, newer_chunks);
        assert_eq!(progress.roster_after_kind, 7);
        assert_eq!(progress.roster_after_key, vec![8]);
        assert_eq!(progress.fanout_after, Some(peer_key.clone()));

        let peer = progress.peers.get_mut(&peer_key).unwrap();
        service_crdt_select_latest_peer_transfer(
            peer,
            progress.latest_transfer,
            &progress.latest_chunks,
        );
        assert_eq!(
            peer.transfer,
            Some(transfer),
            "a frontier refresh cannot interrupt an in-flight peer transfer"
        );
        peer.next_chunk = chunks.len() as u32;
        service_crdt_select_latest_peer_transfer(
            peer,
            progress.latest_transfer,
            &progress.latest_chunks,
        );
        assert_eq!(peer.transfer, Some(newer_transfer));
        assert_eq!(peer.next_chunk, 0);

        let after_two_cycles = selected_at + SERVICE_CRDT_SYNC_TRANSFER_STALL * 2;
        peer.next_chunk = 1;
        peer.awaiting_ack_since = None;
        assert!(
            !peer.release_stalled_transfer(after_two_cycles, SERVICE_CRDT_SYNC_TRANSFER_STALL),
            "an acknowledged peer may wait longer than the stall limit for its next fan-out turn"
        );
        assert_eq!(peer.transfer, Some(newer_transfer));
        assert_eq!(peer.next_chunk, 1);

        peer.awaiting_ack_since = selected_at.checked_sub(SERVICE_CRDT_SYNC_TRANSFER_STALL);
        assert!(peer.release_stalled_transfer(selected_at, SERVICE_CRDT_SYNC_TRANSFER_STALL));
        assert!(peer.transfer.is_none());
        assert!(peer.chunks.is_none());

        let retired = vec![0xB6];
        progress.peers.insert(
            retired.clone(),
            CrdtPeerProgress {
                transfer: Some(transfer),
                chunks: Some(chunks),
                ..CrdtPeerProgress::default()
            },
        );
        progress.finish_roster_scan();
        assert!(progress.peers.contains_key(&peer_key));
        assert!(!progress.peers.contains_key(&retired));
        assert!(progress.roster_seen.is_empty());
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn service_crdt_private_floor_requires_a_space_grant() {
        use crate::registry::SyncFloor;

        let peer = libp2p::PeerId::random();
        let check = |floor, space_role| {
            let (routes, registry) = spawn_stub_sync_floor_registry(floor, space_role);
            let allowed = service_crdt_sync_peer_allowed(
                &routes,
                &peer,
                "private-board",
                Duration::from_secs(1),
            );
            drop(routes);
            registry.join().unwrap();
            allowed
        };
        assert!(!check(Some(SyncFloor::Private), AUTH_ROLE_NONE));
        assert!(check(Some(SyncFloor::Private), AUTH_ROLE_READONLY));
        assert!(check(Some(SyncFloor::Member), AUTH_ROLE_NONE));
        assert!(
            !check(None, AUTH_ROLE_READONLY),
            "an unknown floor must deny even an otherwise granted enrolled peer"
        );
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn service_crdt_fanout_cursor_advances_after_failed_attempt_windows() {
        let peers = (0u8..12).map(|peer| vec![peer]).collect::<Vec<_>>();
        let mut after = None;
        let mut attempted = BTreeSet::new();
        for _ in 0..3 {
            let order = service_crdt_fanout_order(peers.clone(), after.as_deref());
            let window = &order[..SERVICE_CRDT_SYNC_ATTEMPT_BUDGET];
            // Model every authorization attempt failing: no successful send
            // is needed for the cursor to reach the rest of the roster.
            attempted.extend(window.iter().cloned());
            after = window.last().cloned();
        }
        assert_eq!(attempted.len(), peers.len());

        let wrapped = service_crdt_fanout_order(peers, after.as_deref());
        assert_eq!(
            &wrapped[..SERVICE_CRDT_SYNC_ATTEMPT_BUDGET],
            &[vec![0], vec![1], vec![2], vec![3]]
        );
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn service_crdt_roster_pagination_progresses_beyond_sixteen_pages() {
        use crate::actors::codec::Encode;
        use crate::registry::{MEMBER_KIND_NODE, MemberPage, MemberRow, NODE_ROLE_OBSERVER};
        use crate::value::Value;

        let mut by_prefix = BTreeMap::new();
        while by_prefix.len() < 1_025 {
            let peer = libp2p::PeerId::random();
            by_prefix
                .entry(crate::network::derive_node_prefix(&peer))
                .or_insert(peer);
        }
        let rows = by_prefix
            .into_iter()
            .map(|(prefix, peer)| MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer.to_bytes(),
                prefix,
                role: NODE_ROLE_OBSERVER,
                proof_kind: 0,
                proof_data: Vec::new(),
            })
            .collect::<Vec<_>>();
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let registry = thread::spawn(move || {
            for (index, page_rows) in rows.chunks(64).enumerate() {
                let request = rx.recv().unwrap();
                assert_eq!(
                    intercepted_method_name(&request.msg).as_deref(),
                    Some("members")
                );
                let more = index + 1 < 17;
                let page = MemberPage {
                    members: page_rows.to_vec(),
                    next_kind: MEMBER_KIND_NODE,
                    next_key: page_rows.last().unwrap().prefix.to_be_bytes().to_vec(),
                    more,
                };
                let reply = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &Value::Bytes(page.encode()).encode(),
                );
                assert!(request.reply.send(reply));
            }
        });
        let mut kind = MEMBER_KIND_NODE;
        let mut key = Vec::new();
        let mut peers = BTreeSet::new();
        let mut pages = 0;
        loop {
            let page = service_crdt_replica_roster_page(&routes, kind, key, Duration::from_secs(1))
                .unwrap();
            pages += 1;
            peers.extend(page.peers);
            let Some((next_kind, next_key)) = page.next else {
                break;
            };
            kind = next_kind;
            key = next_key;
        }
        assert_eq!(pages, 17);
        assert_eq!(peers.len(), 1_025);
        drop(routes);
        registry.join().unwrap();
    }

    #[test]
    fn service_transport_peer_is_bound_to_the_exact_claimed_actor() {
        let actor_a = crate::service::ActorId([0xA1; 32]);
        let actor_b = crate::service::ActorId([0xB1; 32]);
        let route = ServiceId::new(0xCAFE, 7);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([1; 32]),
            root_service: crate::service::RootServiceId([2; 32]),
            deployment: crate::service::DeploymentId([3; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };
        let routes = RwLock::new(HashMap::from([
            (
                actor_a,
                ActorRoute {
                    route: route.0,
                    service: service.clone(),
                    consistency: crate::service::ConsistencyMode::Local,
                    replication_id: None,
                    is_role_authority: false,
                    invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
                    authenticated_peer: Some(vec![0xA2]),
                },
            ),
            (
                actor_b,
                ActorRoute {
                    route: route.0,
                    service,
                    consistency: crate::service::ConsistencyMode::Raft,
                    replication_id: Some([0xB3; 32]),
                    is_role_authority: false,
                    invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
                    authenticated_peer: Some(vec![0xB2]),
                },
            ),
        ]));

        assert!(
            authenticated_service_actor_route(&routes, actor_a, route, Some(&[0xA2])).is_some()
        );
        assert!(
            authenticated_service_actor_route(&routes, actor_b, route, Some(&[0xB2])).is_some()
        );
        assert!(
            authenticated_service_actor_route(&routes, actor_b, route, Some(&[0xA2])).is_none(),
            "a colliding Local route owned by peer A cannot authenticate Raft actor B"
        );
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn raft_transport_ack(
        acceptor: crate::service::ActorId,
        acceptor_service: crate::service::ServiceIdentity,
        destination_service: crate::service::ServiceIdentity,
    ) -> Vec<u8> {
        use crate::service::ServiceWire;

        crate::service::RootTreeTransport::PublicationAccepted {
            acceptor,
            acceptor_service,
            service: destination_service,
            input: crate::service::WorkInputId {
                invocation: crate::service::InvocationId([0x91; 32]),
                workflow_step: 0,
            },
            publication: crate::service::Hash([0x92; 32]),
            call: crate::service::CallId([0x93; 32]),
        }
        .encode()
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn networkless_raft_transport_reaches_an_attached_local_root() {
        let actor = crate::service::ActorId([0x81; 32]);
        let acceptor = crate::service::ActorId([0x82; 32]);
        let route = ServiceId::new(0x1234, 7);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([1; 32]),
            root_service: crate::service::RootServiceId([2; 32]),
            deployment: crate::service::DeploymentId([3; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };
        let acceptor_service = crate::service::ServiceIdentity {
            root_service: crate::service::RootServiceId([4; 32]),
            ..service.clone()
        };
        let payload = raft_transport_ack(acceptor, acceptor_service, service.clone());

        let mut node = VosNode::new();
        node.service_actor_routes.write().unwrap().insert(
            actor,
            ActorRoute {
                route: route.0,
                service,
                consistency: crate::service::ConsistencyMode::Raft,
                replication_id: Some([0x83; 32]),
                is_role_authority: false,
                invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
                authenticated_peer: None,
            },
        );
        let (tx, rx) = mpsc::channel();
        node.routes.insert(route.0, tx);

        node.route(Envelope {
            from: ServiceId::new(0, 8),
            to: route,
            payload: payload.clone(),
            authenticated_source_peer: None,
            destination_peer: None,
        });

        let delivered = rx
            .recv_timeout(Duration::from_millis(100))
            .expect("a networkless Raft root receives same-node transport");
        assert_eq!(delivered.payload, payload);
        assert!(node.shared_network.lock().unwrap().is_none());
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn stalled_first_raft_status_probe_does_not_starve_an_alternate_voter() {
        let (stalled_tx, stalled_rx) = mpsc::channel();
        let (leader_tx, leader_rx) = mpsc::channel();
        leader_tx
            .send(crate::network::RaftStatusReply {
                present: true,
                role: crate::network::RaftRole::Leader,
                current_term: 9,
                commit_index: 12,
                last_applied: 12,
                last_log_index: 12,
                members: vec![0x2222],
                joint_old: None,
                active_config_index: Some(12),
                leader_hint: Some(0x2222),
            })
            .unwrap();
        let mut probes = vec![(0x1111, stalled_rx), (0x2222, leader_rx)];
        let started = Instant::now();
        let replies =
            collect_service_raft_status_probes(&mut probes, started + Duration::from_millis(100));
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].0, 0x2222);
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "the first unanswered probe must not consume another per-voter deadline"
        );
        drop(stalled_tx);
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn higher_term_live_status_supersedes_a_stale_cached_leader_hint() {
        let stale = crate::network::RaftStatusReply {
            present: true,
            role: crate::network::RaftRole::Follower,
            current_term: 7,
            commit_index: 11,
            last_applied: 11,
            last_log_index: 11,
            members: vec![0x1111, 0x2222],
            joint_old: None,
            active_config_index: Some(11),
            leader_hint: Some(0x1111),
        };
        let current = crate::network::RaftStatusReply {
            present: true,
            role: crate::network::RaftRole::Leader,
            current_term: 8,
            commit_index: 12,
            last_applied: 12,
            last_log_index: 12,
            members: vec![0x1111, 0x2222],
            joint_old: None,
            active_config_index: Some(12),
            leader_hint: Some(0x2222),
        };
        let ranked =
            ranked_service_raft_leader_observations(vec![(0x1111, stale), (0x2222, current)]);
        assert_eq!(
            ranked.first().and_then(|(_, status)| status.leader_hint),
            Some(0x2222),
            "a lower-term local cache cannot pin transport to its former leader"
        );
        assert_eq!(ranked.len(), 1, "lower terms cannot be fallback routes");
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn exact_raft_bootstrap_survives_a_connected_prefix_collision() {
        let exact = libp2p::PeerId::random();
        let colliding = libp2p::PeerId::random();
        assert_ne!(exact, colliding);
        let shared_prefix = 0x5151;
        let mut candidates = Vec::new();

        push_service_raft_peer_candidate(&mut candidates, shared_prefix, exact);
        push_service_raft_peer_candidate(&mut candidates, shared_prefix, colliding);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], (shared_prefix, Some(exact)));
        assert_eq!(candidates[1], (shared_prefix, Some(colliding)));
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn connected_candidate_cursors_are_per_destination_and_advance_by_actual_window() {
        let peers = (0..32)
            .map(|_| libp2p::PeerId::random())
            .collect::<Vec<_>>();
        let mut cursor_a = 0;
        let mut cursor_b = 0;
        let mut observed_a = HashSet::new();
        let mut observed_b = HashSet::new();

        for _ in 0..2 {
            let (window_a, next_a) = service_raft_connected_candidate_window(
                peers.clone(),
                cursor_a,
                SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES,
            );
            cursor_a = next_a;
            observed_a.extend(window_a);

            let (window_b, next_b) = service_raft_connected_candidate_window(
                peers.clone(),
                cursor_b,
                SERVICE_RAFT_TRANSPORT_MAX_AMBIENT_CANDIDATES,
            );
            cursor_b = next_b;
            observed_b.extend(window_b);
        }

        assert_eq!(observed_a.len(), peers.len());
        assert_eq!(observed_b.len(), peers.len());

        let peers = (0..33)
            .map(|_| libp2p::PeerId::random())
            .collect::<Vec<_>>();
        let mut cursor = 0;
        let mut observed = HashSet::new();
        for _ in 0..3 {
            let (window, next) = service_raft_connected_candidate_window(peers.clone(), cursor, 13);
            assert_eq!(window.len(), 13);
            cursor = next;
            observed.extend(window);
        }
        assert_eq!(
            observed.len(),
            peers.len(),
            "smaller ambient windows must not leave gaps"
        );
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn authenticated_bootstrap_follower_can_introduce_an_unseen_leader() {
        use crate::actors::codec::Encode;
        use crate::registry::{MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberPage, MemberRow};
        use crate::value::Value;

        let follower = libp2p::PeerId::random();
        let follower_prefix = crate::network::derive_node_prefix(&follower);
        let (leader, leader_prefix) = loop {
            let peer = libp2p::PeerId::random();
            let prefix = crate::network::derive_node_prefix(&peer);
            if prefix != follower_prefix {
                break (peer, prefix);
            }
        };
        let follower_member = MemberRow {
            kind: MEMBER_KIND_NODE,
            key: follower.to_bytes(),
            prefix: follower_prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let leader_member = MemberRow {
            kind: MEMBER_KIND_NODE,
            key: leader.to_bytes(),
            prefix: leader_prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let authenticated = HashMap::from([(follower_prefix, (follower, follower_member))]);
        let observations = vec![(
            follower_prefix,
            crate::network::RaftStatusReply {
                present: true,
                role: crate::network::RaftRole::Follower,
                current_term: 12,
                commit_index: 19,
                last_applied: 19,
                last_log_index: 19,
                members: vec![follower_prefix, leader_prefix],
                joint_old: None,
                active_config_index: Some(19),
                leader_hint: Some(leader_prefix),
            },
        )];

        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let registry = thread::spawn(move || {
            let request = registry_rx.recv().expect("leader roster probe arrives");
            let reply = Value::Bytes(
                MemberPage {
                    members: vec![leader_member],
                    next_kind: MEMBER_KIND_IDENTITY,
                    next_key: Vec::new(),
                    more: false,
                }
                .encode(),
            )
            .encode();
            assert!(
                request
                    .reply
                    .send(encode_invoke_envelope(crate::STATUS_DONE, &[], &reply,))
            );
        });

        let local_id = 0x4040;
        assert_eq!(
            resolve_service_raft_leader_observations(
                observations,
                &authenticated,
                &routes,
                local_id,
                Instant::now() + Duration::from_millis(250),
            ),
            Some((leader, ServiceId::new(leader_prefix, local_id)))
        );
        registry.join().unwrap();
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn raft_discovery_ownership_outlives_its_shared_deadline() {
        let started = Instant::now();
        let (deadline, ownership_until) = service_raft_transport_resolution_deadlines(started);

        assert_eq!(
            deadline.duration_since(started),
            SERVICE_RAFT_TRANSPORT_RESOLUTION_TIMEOUT
        );
        assert_eq!(
            ownership_until.duration_since(deadline),
            SERVICE_RAFT_TRANSPORT_RESOLUTION_OWNERSHIP_GRACE
        );
        assert!(
            ownership_until > deadline,
            "a retry cannot replace the generation while its resolver may still return"
        );
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn exact_bootstrap_budget_is_independent_of_ambient_candidates() {
        let started = Instant::now();
        let deadline = started + SERVICE_RAFT_TRANSPORT_RESOLUTION_TIMEOUT;
        let (exact_budget, auth_deadline) = service_raft_transport_auth_windows(started, deadline);

        assert_eq!(exact_budget, Duration::from_millis(500));
        assert_eq!(
            auth_deadline.duration_since(started),
            Duration::from_millis(500)
        );
        assert_eq!(
            service_raft_transport_status_deadline(auth_deadline, deadline).duration_since(started),
            Duration::from_millis(750),
            "the final quarter remains reserved for unseen leader authentication"
        );
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn slow_raft_leader_discovery_is_off_router_and_coalesced() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer = libp2p::PeerId::from(key.public());
        let prefix = crate::network::derive_node_prefix(&local_peer);
        let network = Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig {
                keypair: key,
                local_prefix: prefix,
                listen: Vec::new(),
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            },
        ));
        let remote_peer = libp2p::PeerId::random();
        let actor = crate::service::ActorId([0x84; 32]);
        let acceptor = crate::service::ActorId([0x85; 32]);
        let remote_route = ServiceId::new(crate::network::derive_node_prefix(&remote_peer), 9);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([5; 32]),
            root_service: crate::service::RootServiceId([6; 32]),
            deployment: crate::service::DeploymentId([7; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };
        let payload = raft_transport_ack(
            acceptor,
            crate::service::ServiceIdentity {
                root_service: crate::service::RootServiceId([8; 32]),
                ..service.clone()
            },
            service.clone(),
        );

        let mut node = VosNode::with_prefix(prefix);
        *node.shared_network.lock().unwrap() = Some(network.clone());
        node.service_actor_routes.write().unwrap().insert(
            actor,
            ActorRoute {
                route: remote_route.0,
                service,
                consistency: crate::service::ConsistencyMode::Raft,
                replication_id: Some([0x86; 32]),
                is_role_authority: false,
                invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
                authenticated_peer: Some(remote_peer.to_bytes()),
            },
        );
        let (registry_tx, registry_rx) = mpsc::channel();
        node.invoke_routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let unrelated = ServiceId::new(prefix, 10);
        let (unrelated_tx, unrelated_rx) = mpsc::channel();
        node.routes.insert(unrelated.0, unrelated_tx);

        let envelope = Envelope {
            from: ServiceId::new(prefix, 11),
            to: remote_route,
            payload,
            authenticated_source_peer: None,
            destination_peer: None,
        };
        let started = Instant::now();
        node.route(envelope.clone());
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "leader lookup must never run on the global router"
        );
        let blocked_probe = registry_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("the off-router resolver reaches the deliberately blocked registry");

        for _ in 0..4 {
            node.route(envelope.clone());
        }
        assert!(
            matches!(registry_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "durable duplicate retries coalesce behind one lookup"
        );

        node.route(Envelope {
            from: ServiceId::new(prefix, 12),
            to: unrelated,
            payload: b"unrelated".to_vec(),
            authenticated_source_peer: None,
            destination_peer: None,
        });
        assert_eq!(
            unrelated_rx
                .recv_timeout(Duration::from_millis(100))
                .unwrap()
                .payload,
            b"unrelated"
        );
        assert_eq!(
            node.service_raft_transport_resolutions
                .lock()
                .unwrap()
                .len(),
            1,
            "one destination has at most one resolver/cache entry"
        );

        drop(blocked_probe);
        node.shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(25));
        drop(node);
        if let Ok(network) = Arc::try_unwrap(network) {
            network.join();
        }
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn raft_transport_resolves_different_source_and_destination_leaders() {
        use crate::actors::codec::Encode;
        use crate::network::{
            Network, NetworkConfig, RaftAppendResult, RaftEntry, RaftRole, RaftRpcHandler,
            RaftStatusReply, RaftVoteResult,
        };
        use crate::registry::{MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberPage, MemberRow};
        use crate::value::Value;

        struct StatusHandler {
            me: u16,
            leader: Arc<AtomicU16>,
            members: Vec<u16>,
        }

        impl RaftRpcHandler for StatusHandler {
            fn local_status(&self) -> Option<RaftStatusReply> {
                Some(self.handle_status(&[0; 32]))
            }

            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }

            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> RaftVoteResult {
                RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }

            fn handle_status(&self, _replication_id: &[u8; 32]) -> RaftStatusReply {
                let leader = self.leader.load(Ordering::Relaxed);
                RaftStatusReply {
                    present: true,
                    role: if self.me == leader {
                        RaftRole::Leader
                    } else {
                        RaftRole::Follower
                    },
                    current_term: 7,
                    commit_index: 11,
                    last_applied: 11,
                    last_log_index: 11,
                    members: self.members.clone(),
                    joint_old: None,
                    active_config_index: Some(11),
                    leader_hint: Some(leader),
                }
            }
        }

        let key_a = libp2p::identity::Keypair::generate_ed25519();
        let peer_a = libp2p::PeerId::from(key_a.public());
        let prefix_a = crate::network::derive_node_prefix(&peer_a);
        let (key_b, peer_b, prefix_b) = loop {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let peer = libp2p::PeerId::from(key.public());
            let prefix = crate::network::derive_node_prefix(&peer);
            if prefix != prefix_a {
                break (key, peer, prefix);
            }
        };
        let members = vec![prefix_a, prefix_b];
        let source_replication = [0xA1; 32];
        let destination_replication = [0xB1; 32];
        let source_leader = Arc::new(AtomicU16::new(prefix_a));
        let destination_leader = Arc::new(AtomicU16::new(prefix_b));
        let network_a = Network::start(NetworkConfig {
            keypair: key_a,
            local_prefix: prefix_a,
            listen: Vec::new(),
            bootstrap: Vec::new(),
            auto_dial_mdns: false,
        });
        let network_b = Network::start(NetworkConfig {
            keypair: key_b,
            local_prefix: prefix_b,
            listen: Vec::new(),
            bootstrap: Vec::new(),
            auto_dial_mdns: false,
        });
        network_a.register_raft_handler(
            destination_replication,
            Arc::new(StatusHandler {
                me: prefix_a,
                leader: destination_leader.clone(),
                members: members.clone(),
            }),
        );
        network_b.register_raft_handler(
            source_replication,
            Arc::new(StatusHandler {
                me: prefix_b,
                leader: source_leader.clone(),
                members,
            }),
        );

        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let rows = vec![
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_b.to_bytes(),
                prefix: prefix_b,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_a.to_bytes(),
                prefix: prefix_a,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_a.to_bytes(),
                prefix: prefix_a,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_b.to_bytes(),
                prefix: prefix_b,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_a.to_bytes(),
                prefix: prefix_a,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_b.to_bytes(),
                prefix: prefix_b,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_b.to_bytes(),
                prefix: prefix_b,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_a.to_bytes(),
                prefix: prefix_a,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
        ];
        let registry = thread::spawn(move || {
            for row in rows {
                let request = registry_rx.recv().expect("leader roster probe arrives");
                let reply = Value::Bytes(
                    MemberPage {
                        members: vec![row],
                        next_kind: MEMBER_KIND_IDENTITY,
                        next_key: Vec::new(),
                        more: false,
                    }
                    .encode(),
                )
                .encode();
                assert!(request.reply.send(encode_invoke_envelope(
                    crate::STATUS_DONE,
                    &[],
                    &reply,
                )));
            }
        });

        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([1; 32]),
            root_service: crate::service::RootServiceId([2; 32]),
            deployment: crate::service::DeploymentId([3; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };
        let destination = ActorRoute {
            route: ServiceId::new(prefix_a, 0x4040).0,
            service: service.clone(),
            consistency: crate::service::ConsistencyMode::Raft,
            replication_id: Some(destination_replication),
            is_role_authority: false,
            invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
            authenticated_peer: None,
        };
        let source = ActorRoute {
            route: ServiceId::new(prefix_b, 0x3030).0,
            service,
            consistency: crate::service::ConsistencyMode::Raft,
            replication_id: Some(source_replication),
            is_role_authority: false,
            invoke_timeout: SERVICE_LOCAL_INVOKE_TIMEOUT,
            authenticated_peer: None,
        };

        assert_eq!(
            resolve_service_raft_leader_route(&destination, &network_a, &routes),
            Some((peer_b, ServiceId::new(prefix_b, 0x4040))),
            "delivery follows the destination group's B leader"
        );
        assert_eq!(
            resolve_service_raft_leader_route(&source, &network_b, &routes),
            Some((peer_a, ServiceId::new(prefix_a, 0x3030))),
            "acknowledgement independently follows the source group's A leader"
        );

        destination_leader.store(prefix_a, Ordering::Relaxed);
        source_leader.store(prefix_b, Ordering::Relaxed);
        assert_eq!(
            resolve_service_raft_leader_route(&destination, &network_a, &routes),
            Some((peer_a, ServiceId::new(prefix_a, 0x4040))),
            "a destination failover replaces the bootstrap route on the next retry"
        );
        assert_eq!(
            resolve_service_raft_leader_route(&source, &network_b, &routes),
            Some((peer_b, ServiceId::new(prefix_b, 0x3030))),
            "acknowledgement routing follows an independent source failover"
        );

        drop(routes);
        registry.join().unwrap();
        network_a.join();
        network_b.join();
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    #[test]
    fn raft_typed_invoke_budget_covers_every_bounded_stage() {
        assert_eq!(
            service_raft_invoke_timeout(5_000),
            Duration::from_secs(35),
            "voter auth + private staging + read barrier + genesis + admission + apply + margin",
        );
        assert_eq!(
            service_raft_invoke_timeout(2_000),
            Duration::from_secs(20),
            "the end-to-end budget follows the configured proposal timeout",
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn service_exact_destination_precedes_a_colliding_local_prefix() {
        let remote_key = libp2p::identity::Keypair::generate_ed25519();
        let remote_peer = libp2p::PeerId::from(remote_key.public());
        let peer_bytes = remote_peer.to_bytes();
        let colliding_prefix = crate::network::derive_node_prefix(&remote_peer);
        let route = ServiceId::new(colliding_prefix, 7);
        let actor = crate::service::ActorId([0xD1; 32]);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([4; 32]),
            root_service: crate::service::RootServiceId([5; 32]),
            deployment: crate::service::DeploymentId([6; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };

        let mut node = VosNode::with_prefix(colliding_prefix);
        node.bind_service_actor_route(
            actor,
            service,
            crate::service::ConsistencyMode::Local,
            route,
            peer_bytes.clone(),
        )
        .unwrap();
        let (local_tx, local_rx) = mpsc::channel();
        node.routes.insert(route.0, local_tx);

        node.route(Envelope {
            from: ServiceId::new(colliding_prefix, 8),
            to: route,
            payload: b"VRTW collision regression".to_vec(),
            authenticated_source_peer: None,
            destination_peer: Some(peer_bytes.clone()),
        });

        assert!(
            matches!(local_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "an exact remote destination must never fall through to the colliding local route"
        );

        node.route(Envelope {
            from: route,
            to: route,
            payload: b"VRTW inbound collision regression".to_vec(),
            authenticated_source_peer: Some(peer_bytes.clone()),
            destination_peer: None,
        });
        let inbound = local_rx
            .try_recv()
            .expect("an inbound authenticated source still reaches its local destination");
        assert_eq!(
            inbound.authenticated_source_peer,
            Some(peer_bytes),
            "local dispatch retains the exact source for actor-level authentication"
        );
        assert!(inbound.destination_peer.is_none());
    }

    #[test]
    fn service_ingress_uses_the_canonical_peer_subject_identity() {
        let peer = vec![0xaa, 0xbb, 0xcc];
        let routes = RwLock::new(HashMap::new());
        assert_eq!(
            service_root_origin(&crate::actors::Caller::Peer(peer.clone()), &routes),
            Some(crate::service::Origin::Member(
                crate::actors::context::authenticated_peer_subject(&peer)
            ))
        );
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    #[test]
    fn raft_redirect_and_delegation_preserve_the_observed_origin() {
        for origin in [
            crate::service::Origin::System,
            crate::service::Origin::Anonymous,
            crate::service::Origin::Member(crate::service::SubjectId([7; 32])),
            crate::service::Origin::Actor(crate::service::ActorId([8; 32])),
        ] {
            let redirect = encode_service_raft_redirect(41, origin, false);
            assert_eq!(
                decode_service_raft_redirect(&redirect),
                Some(RaftRedirect {
                    leader_prefix: 41,
                    origin,
                    root_upgrade_request: false,
                }),
                "the follower's authenticated origin survives leader selection",
            );
            let delegated =
                encode_service_raft_delegation(origin, true, false, false, b"root ingress");
            assert_eq!(
                decode_service_raft_delegation(&delegated),
                Ok(Some(RaftDelegatedIngress {
                    origin,
                    preserve_envelope: true,
                    role_authority_request: false,
                    root_upgrade_request: false,
                    ingress: b"root ingress".to_vec(),
                })),
            );
        }
        let leadership =
            crate::service::ReplicatedServiceError::Log(crate::commit::CommitError::LeadershipLost);
        assert_eq!(
            decode_service_raft_redirect(
                &encode_service_raft_leadership_redirect(
                    &leadership,
                    Some(42),
                    41,
                    crate::service::Origin::System,
                    false,
                )
                .expect("a different current leader is redirectable"),
            ),
            Some(RaftRedirect {
                leader_prefix: 42,
                origin: crate::service::Origin::System,
                root_upgrade_request: false,
            }),
        );
        assert!(
            encode_service_raft_leadership_redirect(
                &leadership,
                Some(41),
                41,
                crate::service::Origin::System,
                false,
            )
            .is_none(),
            "a stale self hint must fail closed",
        );
        assert!(
            encode_service_raft_leadership_redirect(
                &crate::service::ReplicatedServiceError::Log(crate::commit::CommitError::Config(
                    "corrupt log".into()
                ),),
                Some(42),
                41,
                crate::service::Origin::System,
                false,
            )
            .is_none(),
            "non-leadership replication failures are not retryable redirects",
        );
        let authority = encode_service_raft_delegation(
            crate::service::Origin::System,
            true,
            true,
            false,
            b"authority ingress",
        );
        assert_eq!(
            decode_service_raft_delegation(&authority),
            Ok(Some(RaftDelegatedIngress {
                origin: crate::service::Origin::System,
                preserve_envelope: true,
                role_authority_request: true,
                root_upgrade_request: false,
                ingress: b"authority ingress".to_vec(),
            })),
            "the host-private marker survives only inside authenticated Raft delegation",
        );
        let upgrade = encode_service_raft_delegation(
            crate::service::Origin::System,
            true,
            false,
            true,
            b"upgrade ingress",
        );
        assert_eq!(
            decode_service_raft_delegation(&upgrade),
            Ok(Some(RaftDelegatedIngress {
                origin: crate::service::Origin::System,
                preserve_envelope: true,
                role_authority_request: false,
                root_upgrade_request: true,
                ingress: b"upgrade ingress".to_vec(),
            })),
            "the upgrade marker survives only inside authenticated Raft delegation",
        );
        assert!(
            decode_service_raft_delegation(b"ordinary ingress")
                .unwrap()
                .is_none()
        );
        let mut invalid = encode_service_raft_delegation(
            crate::service::Origin::System,
            true,
            false,
            false,
            b"root ingress",
        );
        invalid[4] = 2;
        assert!(decode_service_raft_delegation(&invalid).is_err());
        invalid[4] = 0;
        invalid[5] = 2;
        assert!(decode_service_raft_delegation(&invalid).is_err());
        invalid[5] = 0;
        invalid[6] = 2;
        assert!(decode_service_raft_delegation(&invalid).is_err());
        assert!(
            decode_service_raft_delegation(b"NOPE\x00\x03bad")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn send_reply_capped_drops_oversized_payload() {
        let (tx, rx) = mpsc::channel();
        // One byte over the cap.
        assert!(!send_reply_capped(
            ReplyChannel::Sync(tx),
            vec![0u8; MAX_PRODUCER_REPLY + 1],
            ServiceId(1),
        ));
        // Sender dropped without sending → recv yields Err(Disconnected).
        // External_invoke maps that to None, surfacing as
        // InvokeError::NotFound at the caller's PVM.
        assert!(
            rx.recv().is_err(),
            "tx should have been dropped without a send"
        );
    }

    #[test]
    fn send_reply_reports_a_cancelled_consumer() {
        let (tx, rx) = mpsc::channel();
        drop(rx);
        assert!(!send_reply_capped(
            ReplyChannel::Sync(tx),
            vec![1, 2, 3],
            ServiceId(1)
        ));
    }

    #[test]
    fn service_host_envelopes_preserve_typed_failures() {
        use crate::actors::client::{CallError, ClientError};

        assert!(matches!(
            decode_host_invoke_envelope(&encode_invoke_envelope(crate::STATUS_FORBIDDEN, &[], &[])),
            Err(ClientError::Forbidden)
        ));
        assert!(matches!(
            decode_host_invoke_envelope(&encode_invoke_envelope(crate::STATUS_NOT_FOUND, &[], &[])),
            Err(ClientError::NotFound)
        ));
        assert!(matches!(
            decode_host_invoke_envelope(&encode_invoke_envelope(crate::STATUS_PANICKED, &[], &[])),
            Err(ClientError::Call(CallError::Panicked))
        ));
    }

    #[test]
    fn invoke_forward_check_caps_depth() {
        let chain: Vec<u32> = (1..=MAX_CROSS_AGENT_DEPTH as u32).collect();
        assert_eq!(chain.len(), MAX_CROSS_AGENT_DEPTH);
        // At cap, even a fresh target is rejected.
        assert_eq!(
            check_invoke_forward(&chain, 9999),
            InvokeForwardCheck::DepthExceeded,
        );
        // One under cap is fine.
        let chain = &chain[..MAX_CROSS_AGENT_DEPTH - 1];
        assert_eq!(
            check_invoke_forward(chain, 9999),
            InvokeForwardCheck::Allowed,
        );
    }

    #[test]
    fn service_id_topology() {
        let id = ServiceId::new(0x00A3, 5);
        assert_eq!(id.0, 0x00A3_0005);
        assert_eq!(id.node_prefix(), 0x00A3);
        assert_eq!(id.local_id(), 5);
        assert!(id.is_on_node(0x00A3));
        assert!(!id.is_on_node(0));
        assert!(!id.is_local());
    }

    #[test]
    fn zero_prefix_ids_address_local_services() {
        let id = ServiceId(3);
        assert_eq!(id.node_prefix(), 0);
        assert_eq!(id.local_id(), 3);
        assert!(id.is_local());
        assert!(id.is_on_node(0));
    }

    #[test]
    fn registry_is_zero() {
        assert_eq!(ServiceId::REGISTRY.0, 0);
        assert_eq!(ServiceId::REGISTRY.node_prefix(), 0);
        assert_eq!(ServiceId::REGISTRY.local_id(), 0);
    }

    #[test]
    fn proof_blob_persists_across_restart() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vos_proof_blob_{}_{}", std::process::id(), stamp));

        // Round 1: put a blob with disk backing.
        let bytes = b"persistence-test-blob".to_vec();
        let hash = {
            let node = VosNode::new().with_proof_blobs_dir(&dir);
            let h = node.put_proof_blob(bytes.clone());
            assert_eq!(node.get_proof_blob(&h).as_deref(), Some(bytes.as_slice()));
            h
        };
        // The disk file exists with the expected name.
        let path = dir.join(proof_blob_filename(&hash));
        assert!(
            path.exists(),
            "put must write through to {}",
            path.display()
        );

        // Round 2: fresh VosNode against the same dir — hot cache is
        // empty but get_proof_blob lazy-loads from disk.
        let node2 = VosNode::new().with_proof_blobs_dir(&dir);
        // Sanity: a fresh node with no disk dir wouldn't see this blob.
        let bare = VosNode::new();
        assert!(bare.get_proof_blob(&hash).is_none());
        // The disk-backed node does.
        assert_eq!(
            node2.get_proof_blob(&hash).as_deref(),
            Some(bytes.as_slice()),
            "node restart against same dir must recover blob from disk",
        );
        // And the lazy-load populated the hot cache, so a second
        // get hits the fast path (we can't observe that directly
        // here, but we can at least assert idempotence).
        assert_eq!(
            node2.get_proof_blob(&hash).as_deref(),
            Some(bytes.as_slice()),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_blob_in_memory_only_without_dir() {
        // No `with_proof_blobs_dir` — hot cache only, no disk side
        // effects. Pinned so a future change doesn't silently make
        // the default behaviour write to some implicit path.
        let node = VosNode::new();
        let hash = node.put_proof_blob(b"hot-cache-only".to_vec());
        assert!(node.get_proof_blob(&hash).is_some());
        // Drop + recreate — fresh node has nothing.
        drop(node);
        let node2 = VosNode::new();
        assert!(node2.get_proof_blob(&hash).is_none());
    }

    #[test]
    fn node_assigns_global_ids() {
        let node = VosNode::with_prefix(0x0042);
        let id1 = node.alloc_id();
        let id2 = node.alloc_id();
        assert_eq!(id1, ServiceId::new(0x0042, 1));
        assert_eq!(id2, ServiceId::new(0x0042, 2));
        assert!(id1.is_on_node(0x0042));
    }

    #[test]
    #[cfg(feature = "storage")]
    fn extension_state_persists_across_restarts() {
        // EchoExtension has a `count` field that increments on each echo.
        // Run the worker, send a few messages, shut down. Restart with
        // the same redb path — the count should resume where it left off.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-extension first");
            return;
        }

        // Use a temp data directory
        let data_dir =
            std::env::temp_dir().join(format!("vos_test_persist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let send_echo = |node: &VosNode, target: ServiceId, text: &str| {
            let msg = Msg::new("echo").with("text", text);
            let encoded = msg.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            if let Some(tx) = node.routes.get(&target.0) {
                tx.send(Envelope {
                    from: ServiceId(0),
                    to: target,
                    payload,
                    authenticated_source_peer: None,
                    destination_peer: None,
                })
                .unwrap();
            }
        };

        // ── First run: send 2 echoes ────────────────────────────────
        {
            let mut node = VosNode::new();
            let id =
                node.register_extension(ExtensionConfig::new(echo_path.clone()).persist(&data_dir));
            send_echo(&node, id, "first");
            send_echo(&node, id, "second");
            node.run();
            let _ = node.collect();
        }

        // ── Second run: state should be restored, count starts at 2 ──
        {
            let mut node = VosNode::new();
            let id = node.register_extension(ExtensionConfig::new(echo_path).persist(&data_dir));
            send_echo(&node, id, "third");
            node.run();
            let _ = node.collect();
        }

        // Verify by opening the db directly and checking the persisted state
        use crate::commit::STATE_TABLE;
        let db_path = data_dir.join("extensions").join("echo_extension.redb");
        let db = redb::Database::open(&db_path).expect("open db");
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(STATE_TABLE).unwrap();
        let bytes = table
            .get("actor")
            .unwrap()
            .expect("state present")
            .value()
            .to_vec();

        // The v2 envelope is 24 bytes (magic, declared version, direct-state
        // fingerprint), followed by EchoExtension's single archived u32.
        assert_eq!(&bytes[..8], b"VOSXST02");
        assert_eq!(bytes.len(), 28, "state envelope plus one archived u32");
        let count = u32::from_le_bytes(bytes[24..].try_into().unwrap());
        assert_eq!(count, 3, "expected 3 echoes total across both runs");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "storage")]
    fn extension_handler_panic_does_not_persist_partial_state() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-extension first");
            return;
        }

        use crate::actors::codec::Encode;
        use crate::actors::value::{Msg, Value};
        let payload = |method: &str| {
            let encoded = Msg::new(method).encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            payload
        };
        let echo_payload = || {
            let encoded = Msg::new("echo").with("text", "committed").encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            payload
        };
        let data_dir = std::env::temp_dir().join(format!(
            "vos_extension_panic_{}_{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let id = ServiceId(0x00ff_1020);

        {
            let mut node = VosNode::new();
            node.register_extension_at_id(
                ExtensionConfig::new(echo_path.clone())
                    .with_name("panic-rollback")
                    .persist(&data_dir),
                id,
            );
            assert!(node.invoke(id, echo_payload()).is_some());
            assert_eq!(node.invoke(id, payload("mutate_then_panic")), None);
            let results = node.collect();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].panics, 1);
            assert!(
                results[0]
                    .error
                    .as_deref()
                    .is_some_and(|error| { error.contains("refusing to retain partial state") })
            );
        }

        {
            let mut node = VosNode::new();
            node.register_extension_at_id(
                ExtensionConfig::new(echo_path)
                    .with_name("panic-rollback")
                    .persist(&data_dir),
                id,
            );
            let count = node.invoke(id, payload("count")).expect("restored count");
            let count: Value = crate::Decode::decode(&count);
            assert_eq!(count.as_u32(), Some(1));
            let results = node.collect();
            assert_eq!(results[0].error, None);
        }

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "http-client")]
    fn extension_does_http_fetch() {
        // Loads fetcher-extension and asks it to GET a URL.
        // Uses example.com which is stable and small. Skips on no network.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let path = workspace
            .join("target")
            .join(profile)
            .join("libfetcher_extension.so");
        if !path.exists() {
            eprintln!("skipping extension_does_http_fetch: build fetcher-extension first");
            return;
        }

        let mut node = VosNode::new();
        let fetcher_id = node.register_extension(ExtensionConfig::new(path));

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let msg = Msg::new("status").with("url", "https://example.com");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        if let Some(tx) = node.routes.get(&fetcher_id.0) {
            tx.send(Envelope {
                from: ServiceId(0),
                to: fetcher_id,
                payload,
                authenticated_source_peer: None,
                destination_peer: None,
            })
            .unwrap();
        }

        node.run();
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "fetcher worker {} panicked", r.id);
        }
    }

    #[test]
    fn extension_to_extension_ask() {
        // This test requires both echo-extension and proxy-extension to be built.
        // Run: cargo build -p echo-extension -p proxy-extension
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let proxy_path = workspace
            .join("target")
            .join(profile)
            .join("libproxy_extension.so");

        if !echo_path.exists() || !proxy_path.exists() {
            eprintln!("skipping extension_to_extension_ask: build workers first");
            return;
        }

        let mut node = VosNode::new();

        // Register echo worker — gets ServiceId 1
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));

        // Build init args for proxy: target = echo's ServiceId
        use crate::actors::codec::Encode;
        use crate::actors::value::{Args, Msg};
        let proxy_args = Args::new().with("target", echo_id.0);
        let proxy_id = node.register_extension(ExtensionConfig::with_args(proxy_path, &proxy_args));

        // Send a "proxy" message to the proxy worker (no target arg now —
        // the proxy already knows its target from init args)
        let msg = Msg::new("proxy").with("text", "hello via proxy");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        // Inject the message by sending directly to proxy's route
        if let Some(tx) = node.routes.get(&proxy_id.0) {
            tx.send(Envelope {
                from: ServiceId(0), // pretend it's from the registry
                to: proxy_id,
                payload,
                authenticated_source_peer: None,
                destination_peer: None,
            })
            .unwrap();
        }

        // Run the node — proxy asks echo, echo replies, proxy replies back
        node.run();
        let results = node.collect();

        // Both workers should complete without panics
        for r in &results {
            assert_eq!(r.panics, 0, "worker {} panicked", r.id);
        }
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", ServiceId(3)), "svc:3");
        assert_eq!(format!("{}", ServiceId::new(0x00A3, 5)), "svc:00a3:5");
        assert_eq!(format!("{}", ServiceId::REGISTRY), "svc:0");
    }

    /// Periodic native `tick()` end-to-end. Loads echo at id 1, then heartbeat
    /// configured with a 100ms
    /// `tick_ms`. The host's tick timer dispatches heartbeat's `tick`, which
    /// pings echo once per tick via `ctx.ask`. After letting it tick
    /// for ~550ms, reads echo's `count` through an `InvokeHandle` and asserts
    /// the host actually drove ≥2 ticks (real asks landed). Then signals shutdown and confirms
    /// every extension exits cleanly (no panic).
    #[test]
    fn tick_extension_originates_asks() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let heartbeat_path = workspace
            .join("target")
            .join(profile)
            .join("libheartbeat_extension.so");

        if !echo_path.exists() || !heartbeat_path.exists() {
            eprintln!(
                "skipping tick_extension_originates_asks: \
                 build echo-extension and heartbeat-extension first"
            );
            return;
        }

        // Heartbeat targets ServiceId(1) by default — register echo
        // first so it lands at id 1.
        let mut node = VosNode::new();
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));
        assert_eq!(
            echo_id.0, 1,
            "echo should land at id 1 (heartbeat default target)"
        );

        // The whole point of the phase: the host timer drives the ping, not a
        // self-spun `run()` loop. 100ms cadence → ~5 ticks in the window below.
        let _heartbeat_id =
            node.register_extension(ExtensionConfig::new(heartbeat_path).with_tick_ms(100));

        // Reader thread: let several ticks elapse, read echo's ping count
        // through a thread-safe invoke handle (the node itself is busy in
        // `run_forever` on this thread), stash it, then wind the node down.
        let handle = node.invoke_handle();
        let shutdown = node.shutdown_handle();
        let pings = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let reader = std::thread::spawn({
            let pings = pings.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(550));
                use crate::Decode;
                use crate::actors::codec::Encode;
                use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
                let msg = Msg::new("count");
                let mut payload = vec![TAG_DYNAMIC];
                payload.extend_from_slice(&msg.encode());
                if let Some(reply) = handle.invoke_with_timeout(
                    ServiceId(1),
                    payload,
                    std::time::Duration::from_secs(2),
                ) {
                    let n = match <Value as Decode>::try_decode(&reply) {
                        Some(Value::U32(n)) => n,
                        Some(Value::U64(n)) => n as u32,
                        _ => 0,
                    };
                    pings.store(n, std::sync::atomic::Ordering::Relaxed);
                }
                shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });

        node.run_forever();
        reader.join().expect("reader thread");
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "extension {} panicked: {:?}", r.id, r.error);
        }
        let pings = pings.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            pings >= 2,
            "host tick timer should have driven ≥2 heartbeat→echo pings in ~550ms @100ms; \
             echo.count = {pings}"
        );
    }

    // ── R1: host-side local_id → name reverse map ──────────────────

    #[test]
    fn local_id_of_masks_to_low_16_bits() {
        assert_eq!(local_id_of(0x00A3_0123), 0x0123);
        assert_eq!(local_id_of(0xFFFF_BEEF), 0xBEEF);
        assert_eq!(local_id_of(ServiceId::REGISTRY.0), 0);
    }

    #[test]
    fn with_name_sets_config_name() {
        assert_eq!(
            AgentConfig::new(Vec::new())
                .with_name("counter")
                .name
                .as_deref(),
            Some("counter")
        );
        assert_eq!(
            ExtensionConfig::new("plugin.so")
                .with_name("worker")
                .name
                .as_deref(),
            Some("worker")
        );
        // Default: anonymous, so the reverse map simply gets no row.
        assert_eq!(AgentConfig::new(Vec::new()).name, None);
        assert_eq!(ExtensionConfig::new("plugin.so").name, None);
    }

    #[test]
    fn record_agent_name_populates_and_resolves_prefix_independently() {
        let node = VosNode::with_prefix(0x0042);
        node.record_agent_name(ServiceId::new(0x0042, 0x0321), Some("workspace".into()));
        // Resolvable by the full prefix-scoped id…
        assert_eq!(
            node.agent_name_for(ServiceId::new(0x0042, 0x0321).0)
                .as_deref(),
            Some("workspace")
        );
        // …and by any value sharing the low 16 bits (a replica of the
        // same instance on another node reuses the entry).
        assert_eq!(node.agent_name_for(0x0321).as_deref(), Some("workspace"));
        assert_eq!(
            node.agent_name_for(0xBEEF_0321).as_deref(),
            Some("workspace")
        );
        // An id this node never registered → None (deny-by-omission).
        assert_eq!(node.agent_name_for(0x0999), None);
    }

    #[test]
    fn record_agent_name_seeds_registry_name_without_explicit_name() {
        // vosx registers the registry from a bare AgentConfig (name =
        // None); the well-known registry id still resolves so the gate
        // can treat it uniformly through the map.
        let node = VosNode::new();
        node.record_agent_name(ServiceId::REGISTRY, None);
        assert_eq!(
            node.agent_name_for(ServiceId::REGISTRY.0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
    }

    #[test]
    fn record_agent_name_non_registry_without_name_is_noop() {
        let node = VosNode::new();
        node.record_agent_name(ServiceId::new(0, 0x0500), None);
        assert_eq!(node.agent_name_for(0x0500), None);
    }

    #[test]
    fn instance_name_collision_is_last_writer_wins() {
        // The map keys on the local half only, so two records that share
        // a local id resolve last-writer-wins. This single rule covers
        // both real cases: (a) two different node prefixes carrying the
        // same instance's local id — the cross-node replica path, where
        // both names are identical so the outcome is moot; and (b) two
        // *different* names that hash-collide into the same ~15-bit
        // local on one node — where the survivor also owns the (single)
        // route, so the map never points at a name whose route a
        // different live actor holds. The losing name's actor-local
        // grant is simply dropped (availability), never applied to
        // another actor. Distinct prefixes are used here so the assert
        // is unambiguous; record_agent_name also WARNs on the overwrite.
        let node = VosNode::new();
        node.record_agent_name(ServiceId::new(0x0001, 0x0300), Some("alpha".into()));
        node.record_agent_name(ServiceId::new(0x0002, 0x0300), Some("beta".into()));
        assert_eq!(node.agent_name_for(0x0300).as_deref(), Some("beta"));
    }

    /// The locality boundary: a node-confined agent (the messenger runs
    /// `consistency = "local"`, holding MLS keys + CSPRNG seed + decrypted
    /// plaintext) is reachable through the network dispatch path ONLY by this
    /// daemon's own operator — even though its route is registered and its
    /// name-derived ServiceId is computable by any peer. A non-operator peer
    /// (including a remote admin) is refused; a replicated agent (`Crdt`/
    /// `Raft`) stays reachable by anyone.
    #[test]
    #[cfg(feature = "network")]
    fn dispatch_invoke_gates_node_confined_agent_to_operator() {
        use crate::actors::codec::Encode;
        use crate::actors::run::STATUS_DONE;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0123);

        // Drive one `dispatch_invoke` from `caller` against a target whose
        // AgentInfo carries `consistency`, with the daemon's `operator_peer`
        // set to `operator`. Report whether the agent actually received the
        // request and what the caller got back.
        let run = |consistency: Option<Consistency>,
                   operator: Option<libp2p::PeerId>,
                   caller: libp2p::PeerId|
         -> (bool, Vec<u8>) {
            let (tgt_tx, tgt_rx) = mpsc::channel::<InvokeRequest>();
            let received = Arc::new(AtomicBool::new(false));
            let received_w = received.clone();
            let sink = thread::spawn(move || {
                if let Ok(req) = tgt_rx.recv() {
                    received_w.store(true, Ordering::Relaxed);
                    let _ = req.reply.send(encode_invoke_envelope(
                        STATUS_DONE,
                        &[],
                        &Value::U8(7).encode(),
                    ));
                }
            });
            let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::from([(target.0, tgt_tx)])));
            let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
                target.0,
                AgentInfo {
                    name: Some("messenger".into()),
                    consistency,
                    network_reachable: false,
                },
            )])));
            let mut service = lifecycle_service(routes, Arc::new(Mutex::new(HashMap::new())), info);
            service.operator_peer = operator.map(|p| p.to_bytes());
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new("history").encode());
            let reply = service.dispatch_invoke(Some(caller), 0, target.0, vec![], payload);
            // Drop the service (and thus the route's sender) so a sink the
            // gate skipped unblocks from `recv` and the thread can join.
            drop(service);
            let got = received.load(Ordering::Relaxed);
            sink.join().unwrap();
            (got, reply)
        };

        let operator = libp2p::PeerId::random();
        let other = libp2p::PeerId::random();

        // Confined (`Local`) called by the operator: admitted — the agent
        // receives the call and its reply rides back. This is the operator
        // driving their own device-local messenger via `vosx messenger …`.
        let (op_received, op_reply) = run(Some(Consistency::Local), Some(operator), operator);
        assert!(
            op_received,
            "the device operator must reach its own node-confined agent"
        );
        assert!(
            !op_reply.is_empty(),
            "the confined agent's reply must ride back to the operator"
        );

        // Confined called by a NON-operator peer (e.g. a remote admin): the
        // gate fires before routing — the agent never sees the call and the
        // peer gets an empty, no-such-agent reply (no existence oracle).
        let (other_received, other_reply) = run(Some(Consistency::Local), Some(operator), other);
        assert!(
            !other_received,
            "a non-operator peer must not reach a node-confined agent"
        );
        assert!(
            other_reply.is_empty(),
            "a refused confined invoke must reply empty"
        );

        // Confined with NO operator recorded (`operator_peer = None`): fail
        // closed — even though `caller` would otherwise look like the only
        // identity around, an unset operator admits nobody.
        let (unset_received, _) = run(Some(Consistency::Local), None, operator);
        assert!(
            !unset_received,
            "an unset operator must admit no one to a confined agent"
        );

        // Ephemeral is confined too — a non-operator is refused.
        let (ephemeral_received, _) = run(Some(Consistency::Ephemeral), Some(operator), other);
        assert!(
            !ephemeral_received,
            "a non-operator must not reach an ephemeral agent"
        );

        // Replicated (`Crdt`): no gate — the request reaches the agent and
        // its reply is forwarded back even for a non-operator peer.
        let (crdt_received, crdt_reply) = run(Some(Consistency::Crdt), Some(operator), other);
        assert!(
            crdt_received,
            "a replicated agent must stay reachable over the network"
        );
        assert!(
            !crdt_reply.is_empty(),
            "the replicated agent's reply must be forwarded back"
        );
    }

    /// Private-replica read gate. A bare-`#[msg]` READ on a `Private`-floor
    /// replica is served over the network only to a space member; a WRITE,
    /// and any method on a non-private agent, is left to the normal path.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn dispatch_invoke_gates_private_replica_reads_to_members() {
        use crate::actors::codec::Encode;
        use crate::actors::run::STATUS_DONE;
        use crate::network::NetworkService;
        use crate::registry::SyncFloor;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0150);

        // Drive one dispatch_invoke of `method` against a target the host knows
        // as `agent_name`, with the stub registry granting the caller `role`.
        // Report whether the target agent actually received the request.
        let run = |agent_name: &str, method: &str, role: u8| -> bool {
            let (routes, _reg) = spawn_stub_peer_role_registry(role);
            let (tgt_tx, tgt_rx) = mpsc::channel::<InvokeRequest>();
            routes.lock().unwrap().insert(target.0, tgt_tx);
            let received = Arc::new(AtomicBool::new(false));
            let received_w = received.clone();
            let sink = thread::spawn(move || {
                if let Ok(req) = tgt_rx.recv() {
                    received_w.store(true, Ordering::Relaxed);
                    let _ = req.reply.send(encode_invoke_envelope(
                        STATUS_DONE,
                        &[],
                        &Value::U8(1).encode(),
                    ));
                }
            });
            let names = Arc::new(std::sync::RwLock::new(HashMap::from([(
                local_id_of(target.0),
                agent_name.to_string(),
            )])));
            let mut svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            svc.agent_names = names;
            // Seed the floor directly (the stub registry only answers the
            // peer_role probe, not agent()): `msg-*` names are Private, others
            // Public — exercising the gate itself, not floor resolution.
            let floor = if agent_name.starts_with("msg-") {
                SyncFloor::Private
            } else {
                SyncFloor::Public
            };
            svc.sync_floor_cache
                .write()
                .unwrap()
                .insert(agent_name.to_string(), (floor, Instant::now()));
            let peer = libp2p::PeerId::random();
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new(method).encode());
            let _ = svc.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
            drop(svc);
            let got = received.load(Ordering::Relaxed);
            sink.join().unwrap();
            got
        };

        // Private (`msg-`) READ from a NON-member: refused before routing.
        assert!(
            !run("msg-general-log", "history", AUTH_ROLE_NONE),
            "a non-member must not read a private msg- replica"
        );
        // Private READ from a space member (READONLY): reaches the agent.
        assert!(
            run("msg-general-log", "history", AUTH_ROLE_READONLY),
            "a space member may read a private msg- replica"
        );
        // Private WRITE (`post`) is NOT gated here — it reaches the agent even
        // from a non-member; the actor's own `#[msg(role)]` check decides.
        assert!(
            run("msg-general-log", "post", AUTH_ROLE_NONE),
            "writes are not gated here — they carry the actor's own role check"
        );
        // A non-private agent's read is never gated.
        assert!(
            run("app-counter", "history", AUTH_ROLE_NONE),
            "only msg- replicas are gated"
        );
    }

    /// Raft-join admission probe: `raft_join_authorized` consults the
    /// registry's `node_role` and admits ONLY the VOTER sentinel. An
    /// unenrolled prefix (0), an observer (2), or an unreachable registry
    /// all deny — so a peer an admin never enrolled cannot become a voter.
    #[test]
    #[cfg(feature = "network")]
    fn raft_join_authorized_only_for_enrolled_voter() {
        use crate::network::NetworkService;
        // `reply = Some(b)` stands in for the registry's node_role byte;
        // `None` models no registry route at all (fail closed).
        let check = |reply: Option<u8>| -> bool {
            let routes: InvokeRoutes = match reply {
                Some(b) => spawn_stub_peer_role_registry(b).0,
                None => Arc::new(Mutex::new(HashMap::new())),
            };
            let svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            svc.raft_join_authorized(0x00ab)
        };
        assert!(
            check(Some(NODE_ROLE_REPLY_VOTER)),
            "enrolled VOTER is admitted"
        );
        assert!(!check(Some(0)), "an unenrolled prefix is refused");
        assert!(!check(Some(2)), "an OBSERVER is refused");
        assert!(!check(None), "an unreachable registry fails closed");
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn enrolled_node_sync_gate_binds_the_full_authenticated_peer_id() {
        use crate::actors::codec::Encode;
        use crate::value::Value;

        let mut peers_by_prefix = std::collections::BTreeMap::new();
        let (enrolled_peer, colliding_peer, prefix) = (1u64..=4_096)
            .find_map(|counter| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&counter.to_le_bytes());
                seed[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
                seed[16..24].copy_from_slice(&counter.rotate_left(31).to_le_bytes());
                seed[24..].copy_from_slice(&counter.rotate_left(47).to_le_bytes());
                let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
                    .expect("valid deterministic Ed25519 seed");
                let peer = keypair.public().to_peer_id();
                let prefix = crate::network::derive_node_prefix(&peer);
                peers_by_prefix
                    .insert(prefix, peer)
                    .map(|previous| (previous, peer, prefix))
            })
            .expect("deterministic fixture range contains a compact-prefix collision");
        assert_ne!(enrolled_peer, colliding_peer);
        assert_eq!(crate::network::derive_node_prefix(&enrolled_peer), prefix);
        assert_eq!(crate::network::derive_node_prefix(&colliding_peer), prefix);

        let enrolled_row = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: enrolled_peer.to_bytes(),
            prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let registry = thread::spawn(move || {
            while let Ok(request) = rx.recv() {
                assert_eq!(
                    intercepted_method_name(&request.msg).as_deref(),
                    Some("members")
                );
                let page = crate::registry::MemberPage {
                    members: vec![enrolled_row.clone()],
                    next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                    next_key: Vec::new(),
                    more: false,
                };
                let reply = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &Value::Bytes(page.encode()).encode(),
                );
                assert!(request.reply.send(reply));
            }
        });
        let service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );

        assert!(service.caller_is_enrolled_node(&enrolled_peer));
        assert!(
            !service.caller_is_enrolled_node(&colliding_peer),
            "a prefix collision must not inherit roster enrollment",
        );
        drop(service);
        registry.join().unwrap();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn raft_delegation_binds_the_full_authenticated_peer_id() {
        use crate::actors::codec::Encode;
        use crate::value::Value;

        let voter = libp2p::PeerId::random();
        let colliding_peer = libp2p::PeerId::random();
        let prefix = crate::network::derive_node_prefix(&voter);
        let row = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: voter.to_bytes(),
            prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };

        // Drive the real registry-query wire as well as the pure identity
        // predicate. This catches accidental regressions back to node_role's
        // prefix-only reply.
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let registry_row = row.clone();
        let registry = thread::spawn(move || {
            let request = rx.recv().unwrap();
            assert_eq!(
                intercepted_method_name(&request.msg).as_deref(),
                Some("members")
            );
            let page = crate::registry::MemberPage {
                members: vec![registry_row],
                next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: true,
            };
            let reply = encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                &Value::Bytes(page.encode()).encode(),
            );
            assert!(request.reply.send(reply));
        });
        let service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        let enrolled = service.lookup_node_member(prefix).unwrap();
        registry.join().unwrap();

        assert!(node_member_authenticates_voter(&enrolled, prefix, &voter));
        // Model the preceding 16-bit group-membership check admitting a
        // distinct PeerId with the same compact prefix. Full roster identity
        // still refuses it, so prefix grinding cannot authorize delegation.
        assert!(!node_member_authenticates_voter(
            &enrolled,
            prefix,
            &colliding_peer
        ));

        let observer = crate::registry::MemberRow {
            role: crate::registry::NODE_ROLE_OBSERVER,
            ..row
        };
        assert!(!node_member_authenticates_voter(&observer, prefix, &voter));
        assert!(
            node_member_authenticates_active_slot(&observer, prefix, &voter),
            "a demoted retiring node remains authenticated only while consensus names its slot",
        );

        let status = crate::network::RaftStatusReply {
            present: true,
            role: crate::network::RaftRole::Follower,
            current_term: 7,
            commit_index: 11,
            last_applied: 11,
            last_log_index: 11,
            members: vec![prefix],
            joint_old: None,
            active_config_index: Some(11),
            leader_hint: Some(prefix),
        };
        assert_eq!(
            authenticated_service_raft_leader_peer(&status, &enrolled, prefix),
            Some(voter),
            "outbound authority routing selects the registry's full PeerId, not the prefix map",
        );
        let mut wrong_group = status;
        wrong_group.members.clear();
        assert!(
            authenticated_service_raft_leader_peer(&wrong_group, &enrolled, prefix).is_none(),
            "the same roster peer is not trusted outside the authority's exact Raft group",
        );
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn public_raft_invokes_ignore_a_colliding_prefix_owner() {
        use crate::actors::codec::Encode;
        use crate::actors::run::STATUS_DONE;
        use crate::network::{
            NetworkConfig, NetworkService, RaftAppendResult, RaftRpcHandler, RaftStatusReply,
            RaftVoteResult,
        };
        use crate::value::{Msg, TAG_DYNAMIC, Value};
        use libp2p::{Multiaddr, PeerId, identity};

        struct Status {
            leader: u16,
        }
        impl RaftRpcHandler for Status {
            fn local_status(&self) -> Option<RaftStatusReply> {
                Some(self.handle_status(&[0; 32]))
            }

            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<crate::network::RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }

            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> RaftVoteResult {
                RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }

            fn handle_status(&self, _replication_id: &[u8; 32]) -> RaftStatusReply {
                RaftStatusReply {
                    present: true,
                    role: crate::network::RaftRole::Follower,
                    current_term: 4,
                    commit_index: 8,
                    last_applied: 8,
                    last_log_index: 8,
                    members: vec![self.leader],
                    joint_old: None,
                    active_config_index: Some(8),
                    leader_hint: Some(self.leader),
                }
            }
        }

        struct Leader;
        impl NetworkService for Leader {
            fn dispatch_invoke(
                &self,
                _caller_peer_id: Option<PeerId>,
                _from: u32,
                _to: u32,
                _chain: Vec<u32>,
                msg: Vec<u8>,
            ) -> Vec<u8> {
                assert!(msg.starts_with(&SERVICE_RAFT_DELEGATION_MAGIC));
                if msg.get(4) == Some(&1) {
                    encode_invoke_envelope(STATUS_DONE, &[], b"exact leader")
                } else {
                    b"exact leader".to_vec()
                }
            }
        }

        let caller_key = identity::Keypair::generate_ed25519();
        let voter_key = identity::Keypair::generate_ed25519();
        let caller_peer = PeerId::from(caller_key.public());
        let voter_peer = PeerId::from(voter_key.public());
        let caller_prefix = crate::network::derive_node_prefix(&caller_peer);
        let voter_prefix = crate::network::derive_node_prefix(&voter_peer);
        assert_ne!(caller_prefix, voter_prefix);

        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let caller_network = crate::network::Network::start(NetworkConfig {
            keypair: caller_key,
            local_prefix: caller_prefix,
            listen: vec![listen.clone()],
            bootstrap: vec![],
            auto_dial_mdns: false,
        });
        let listen_deadline = Instant::now() + Duration::from_secs(5);
        let caller_address = loop {
            if let Some(address) = caller_network.listen_addrs().into_iter().next() {
                break address.with(libp2p::multiaddr::Protocol::P2p(caller_peer));
            }
            assert!(Instant::now() < listen_deadline, "caller binds");
            thread::sleep(Duration::from_millis(10));
        };
        let voter_network = crate::network::Network::start(NetworkConfig {
            keypair: voter_key,
            local_prefix: voter_prefix,
            listen: vec![listen],
            bootstrap: vec![caller_address],
            auto_dial_mdns: false,
        });
        voter_network.set_service(Arc::new(Leader));
        let peer_deadline = Instant::now() + Duration::from_secs(10);
        while caller_network.peer_for_prefix(voter_prefix) != Some(voter_peer) {
            assert!(
                Instant::now() < peer_deadline,
                "caller authenticates the enrolled voter"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let replication_id = [0xA7; 32];
        caller_network.register_raft_handler(
            replication_id,
            Arc::new(Status {
                leader: voter_prefix,
            }),
        );

        let actor = crate::service::ActorId([0xA8; 32]);
        let route = ServiceId::new(caller_prefix, 0xA9);
        let service = crate::service::ServiceIdentity {
            space: crate::service::SpaceId([1; 32]),
            root_service: crate::service::RootServiceId([2; 32]),
            deployment: crate::service::DeploymentId([3; 32]),
            service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        };
        let mut node = VosNode::with_prefix(caller_prefix);
        node.service_actor_routes.write().unwrap().insert(
            actor,
            ActorRoute {
                route: route.0,
                service,
                consistency: crate::service::ConsistencyMode::Raft,
                replication_id: Some(replication_id),
                is_role_authority: false,
                invoke_timeout: Duration::from_secs(5),
                authenticated_peer: None,
            },
        );

        let (root_tx, root_rx) = mpsc::channel::<InvokeRequest>();
        node.invoke_routes.lock().unwrap().insert(route.0, root_tx);
        let root = thread::spawn(move || {
            for _ in 0..3 {
                let request = root_rx.recv().unwrap();
                assert!(request.reply.send(encode_service_raft_redirect(
                    voter_prefix,
                    crate::service::Origin::System,
                    false,
                )));
            }
        });

        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        node.invoke_routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let member = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: voter_peer.to_bytes(),
            prefix: voter_prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let registry = thread::spawn(move || {
            for _ in 0..3 {
                let request = registry_rx.recv().unwrap();
                let page = crate::registry::MemberPage {
                    members: vec![member.clone()],
                    next_kind: crate::registry::MEMBER_KIND_NODE,
                    next_key: Vec::new(),
                    more: false,
                };
                assert!(request.reply.send(encode_invoke_envelope(
                    STATUS_DONE,
                    &[],
                    &Value::Bytes(page.encode()).encode(),
                )));
            }
        });

        node.attach_network(caller_network);
        let attached = node.shared_network.lock().unwrap().clone().unwrap();
        let colliding_peer = PeerId::random();
        assert_ne!(colliding_peer, voter_peer);
        // Model a real first-connected prefix collision without spending ~2^16
        // key generations in every test run. The public paths must ignore this
        // lossy owner and select the roster's complete voter PeerId.
        attached.set_prefix_owner_for_test(voter_prefix, colliding_peer);
        assert_eq!(attached.peer_for_prefix(voter_prefix), Some(colliding_peer));

        let mut arguments = vec![TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("ping").encode());
        assert_eq!(
            node.invoke_actor(actor, arguments.clone()).unwrap(),
            b"exact leader"
        );
        assert_eq!(
            node.invoke_actor_wire(actor, arguments, true).unwrap(),
            b"exact leader"
        );
        assert_eq!(
            node.invoke_with_timeout(route, b"raw".to_vec(), Duration::from_secs(5)),
            Some(b"exact leader".to_vec())
        );

        root.join().unwrap();
        registry.join().unwrap();
        let _ = node.collect();
        voter_network.join();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn private_ingress_store_requires_the_exact_raft_leader_and_root_sink() {
        use crate::actors::codec::Encode;
        use crate::network::{NetworkService, RaftAppendResult, RaftInstallSnapshotResult};
        use crate::value::Value;

        struct Status {
            leader: u16,
            members: Vec<u16>,
        }
        impl crate::network::RaftRpcHandler for Status {
            fn local_status(&self) -> Option<crate::network::RaftStatusReply> {
                Some(crate::network::RaftStatusReply {
                    present: true,
                    role: crate::network::RaftRole::Follower,
                    current_term: 7,
                    commit_index: 9,
                    last_applied: 9,
                    last_log_index: 9,
                    members: self.members.clone(),
                    joint_old: None,
                    active_config_index: Some(9),
                    leader_hint: Some(self.leader),
                })
            }
            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<crate::network::RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }
            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> crate::network::RaftVoteResult {
                crate::network::RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }
            fn install_snapshot(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_included_index: u64,
                _last_included_term: u64,
                _offset: u64,
                _done: bool,
                _snapshot: Vec<u8>,
                _members: Vec<u16>,
                _joint_old: Option<Vec<u16>>,
                _active_config_index: Option<u64>,
            ) -> RaftInstallSnapshotResult {
                RaftInstallSnapshotResult {
                    term,
                    bytes_received: 0,
                }
            }
        }

        let leader = libp2p::PeerId::random();
        let leader_prefix = crate::network::derive_node_prefix(&leader);
        let member = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: leader.to_bytes(),
            prefix: leader_prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let registry = thread::spawn(move || {
            let request = registry_rx.recv().unwrap();
            let page = crate::registry::MemberPage {
                members: vec![member],
                next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: false,
            };
            let reply = Value::Bytes(page.encode()).encode();
            let _ = request.reply.send(encode_invoke_envelope(
                crate::actors::run::STATUS_DONE,
                &[],
                &reply,
            ));
            assert!(
                matches!(
                    registry_rx.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "nonmembers must be rejected before registry work",
            );
        });

        let replication_id = [0x61; 32];
        let network = Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig::default(),
        ));
        let receiver_prefix = network.local_prefix();
        network.register_raft_handler(
            replication_id,
            Arc::new(Status {
                leader: leader_prefix,
                members: vec![leader_prefix, receiver_prefix],
            }),
        );
        let mut service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        service.shared_network = Arc::new(Mutex::new(Some(network.clone())));
        let (sidecar_tx, sidecar_rx) = mpsc::sync_channel(1);
        let (quiescence_tx, _quiescence_rx) = mpsc::sync_channel(1);
        service
            .service_private_ingress_routes
            .write()
            .unwrap()
            .insert(
                replication_id,
                Arc::new(PrivateIngressRoute {
                    tx: sidecar_tx,
                    quiescence_tx,
                    barrier: PrivateIngressBarrier::new(),
                    production_trust_policy: None,
                }),
            );
        let bytes = b"exact private ingress".to_vec();
        let reference = crate::service::BlobRef::of_bytes(&bytes);
        let invocation = crate::service::InvocationId([0x62; 32]);
        let expected_bytes = bytes.clone();
        let expected_reference = reference.clone();
        let sink = thread::spawn(move || {
            let upload: PrivateIngressUpload = sidecar_rx.recv().unwrap();
            assert_eq!(upload.invocation, invocation);
            assert_eq!(upload.reference, expected_reference);
            assert_eq!(upload.bytes, expected_bytes);
            assert!(begin_service_private_ingress_upload(&upload));
            upload.reply.send(true).unwrap();
        });
        assert!(service.store_private_ingress(
            leader,
            &replication_id,
            &invocation.0,
            &reference.hash.0,
            reference.len,
            b"exact private ingress".to_vec(),
        ));
        sink.join().unwrap();
        network.register_raft_handler(
            replication_id,
            Arc::new(Status {
                leader: leader_prefix,
                members: vec![receiver_prefix],
            }),
        );
        assert!(
            !service.store_private_ingress(
                leader,
                &replication_id,
                &invocation.0,
                &reference.hash.0,
                reference.len,
                b"exact private ingress".to_vec(),
            ),
            "a sender absent from the current membership is rejected before registry work",
        );
        network.register_raft_handler(
            replication_id,
            Arc::new(Status {
                leader: leader_prefix,
                members: vec![leader_prefix],
            }),
        );
        assert!(
            !service.store_private_ingress(
                leader,
                &replication_id,
                &invocation.0,
                &reference.hash.0,
                reference.len,
                b"exact private ingress".to_vec(),
            ),
            "a replica removed from the current membership cannot accept fresh plaintext",
        );
        registry.join().unwrap();
        drop(service);
        Arc::try_unwrap(network).ok().unwrap().join();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn timed_out_private_ingress_never_crosses_the_durable_boundary_later() {
        let (tx, rx) = mpsc::sync_channel(1);
        let bytes = b"cancel before persistence".to_vec();
        let reference = crate::service::BlobRef::of_bytes(&bytes);
        assert!(!stage_service_private_ingress_through_root(
            &tx,
            crate::service::InvocationId([0x71; 32]),
            reference,
            bytes,
            Duration::from_millis(1),
        ));
        let upload = rx.recv().unwrap();
        assert!(!begin_service_private_ingress_upload(&upload));
        assert_eq!(
            *upload.state.lock().unwrap(),
            PrivateIngressUploadState::Cancelled,
        );
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn raft_join_is_serialized_with_private_admission_and_requires_quiescence() {
        use crate::actors::codec::Encode;
        use crate::network::{NetworkService, RaftAppendResult, RaftJoinResult};
        use crate::value::Value;
        use std::sync::atomic::AtomicUsize;

        struct JoinHandler(AtomicUsize);
        impl crate::network::RaftRpcHandler for JoinHandler {
            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<crate::network::RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }

            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> crate::network::RaftVoteResult {
                crate::network::RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }

            fn handle_join(
                &self,
                _replication_id: &[u8; 32],
                _joiner_prefix: u16,
            ) -> RaftJoinResult {
                self.0.fetch_add(1, Ordering::Relaxed);
                RaftJoinResult::Accepted { joint_index: 9 }
            }
        }

        let joiner = libp2p::PeerId::random();
        let prefix = crate::network::derive_node_prefix(&joiner);
        let member = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: joiner.to_bytes(),
            prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let registry = thread::spawn(move || {
            for _ in 0..2 {
                let request = registry_rx.recv().unwrap();
                let page = crate::registry::MemberPage {
                    members: vec![member.clone()],
                    next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                    next_key: Vec::new(),
                    more: false,
                };
                let reply = Value::Bytes(page.encode()).encode();
                assert!(request.reply.send(encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &reply,
                )));
            }
        });
        let service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        let replication_id = [0x72; 32];
        let (sidecar_tx, _sidecar_rx) = mpsc::sync_channel(1);
        let (quiescence_tx, quiescence_rx) = mpsc::sync_channel(1);
        let route = Arc::new(PrivateIngressRoute {
            tx: sidecar_tx,
            quiescence_tx,
            barrier: PrivateIngressBarrier::new(),
            production_trust_policy: None,
        });
        service
            .service_private_ingress_routes
            .write()
            .unwrap()
            .insert(replication_id, route.clone());
        let handler = Arc::new(JoinHandler(AtomicUsize::new(0)));
        let network = Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig::default(),
        ));
        network.register_raft_handler(replication_id, handler.clone());
        *service.shared_network.lock().unwrap() = Some(network.clone());

        let admission = route.barrier.try_acquire().unwrap();
        assert_eq!(
            service.handle_raft_join(joiner, &replication_id, prefix, None, handler.as_ref()),
            RaftJoinResult::Busy,
            "membership cannot change while private admission owns the barrier",
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        drop(admission);

        let quiescence = thread::spawn(move || {
            quiescence_rx.recv().unwrap().send(true).unwrap();
        });
        assert_eq!(
            service.handle_raft_join(joiner, &replication_id, prefix, None, handler.as_ref()),
            RaftJoinResult::Accepted { joint_index: 9 },
        );
        quiescence.join().unwrap();
        registry.join().unwrap();
        assert_eq!(handler.0.load(Ordering::Relaxed), 1);
        *service.shared_network.lock().unwrap() = None;
        drop(service);
        Arc::try_unwrap(network).ok().unwrap().join();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn raft_voter_replacement_binds_identities_and_private_quiescence() {
        use crate::actors::codec::Encode;
        use crate::network::{
            NetworkService, RaftAppendResult, RaftReplaceVoterResult, RaftRole, RaftStatusReply,
        };
        use crate::value::Value;
        use std::sync::atomic::AtomicUsize;

        struct ReplaceHandler(AtomicUsize, RaftStatusReply);
        impl crate::network::RaftRpcHandler for ReplaceHandler {
            fn local_status(&self) -> Option<RaftStatusReply> {
                Some(self.1.clone())
            }

            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<crate::network::RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }

            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> crate::network::RaftVoteResult {
                crate::network::RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }

            fn handle_replace_voter(
                &self,
                _replication_id: &[u8; 32],
                _old_prefix: u16,
                _replacement_prefix: u16,
            ) -> RaftReplaceVoterResult {
                self.0.fetch_add(1, Ordering::Relaxed);
                RaftReplaceVoterResult::Accepted { joint_index: 12 }
            }
        }

        let operator_key = libp2p::identity::Keypair::generate_ed25519();
        let operator = libp2p::PeerId::from(operator_key.public());
        let network = Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig::default(),
        ));
        let replacement = network.peer_id();
        let old = loop {
            let candidate = libp2p::PeerId::random();
            if crate::network::derive_node_prefix(&candidate)
                != crate::network::derive_node_prefix(&replacement)
            {
                break candidate;
            }
        };
        let old_prefix = crate::network::derive_node_prefix(&old);
        let replacement_prefix = crate::network::derive_node_prefix(&replacement);
        let remote_replacement = loop {
            let candidate = libp2p::PeerId::random();
            let prefix = crate::network::derive_node_prefix(&candidate);
            if prefix != old_prefix && prefix != replacement_prefix {
                break candidate;
            }
        };
        let remote_replacement_prefix = crate::network::derive_node_prefix(&remote_replacement);
        let operation_epoch = 4;
        let space_id = [0x51; 32];
        let sign_replacement =
            |replacement_prefix: u16, replacement_peer: &libp2p::PeerId, epoch: u64| -> [u8; 64] {
                let message = crate::registry::raft_voter_replacement_signed_bytes(
                    &space_id,
                    &[0x73; 32],
                    old_prefix,
                    &old.to_bytes(),
                    replacement_prefix,
                    &replacement_peer.to_bytes(),
                    epoch,
                );
                operator_key.sign(&message).unwrap().try_into().unwrap()
            };
        let operator_signature =
            sign_replacement(replacement_prefix, &replacement, operation_epoch);
        let remote_operator_signature = sign_replacement(
            remote_replacement_prefix,
            &remote_replacement,
            operation_epoch,
        );
        let stale_operator_signature =
            sign_replacement(replacement_prefix, &replacement, operation_epoch - 1);
        assert!(
            !verifies_raft_voter_replacement_operator(
                &operator,
                &[0x52; 32],
                &[0x73; 32],
                old_prefix,
                &old,
                replacement_prefix,
                &replacement,
                operation_epoch,
                &operator_signature,
            ),
            "a voter-replacement attestation cannot be transplanted to a sibling space",
        );
        let rows = vec![
            crate::registry::MemberRow {
                kind: crate::registry::MEMBER_KIND_NODE,
                key: old.to_bytes(),
                prefix: old_prefix,
                // The CLI first demotes the retiring identity so no newly
                // installed root can enroll it during the multi-root scan.
                role: crate::registry::NODE_ROLE_OBSERVER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            crate::registry::MemberRow {
                kind: crate::registry::MEMBER_KIND_NODE,
                key: replacement.to_bytes(),
                prefix: replacement_prefix,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
            crate::registry::MemberRow {
                kind: crate::registry::MEMBER_KIND_NODE,
                key: remote_replacement.to_bytes(),
                prefix: remote_replacement_prefix,
                role: crate::registry::NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
        ];
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        routes
            .lock()
            .unwrap()
            .insert(ServiceId::REGISTRY.0, registry_tx);
        let registry_rows = rows.clone();
        let registry = thread::spawn(move || {
            while let Ok(request) = registry_rx.recv() {
                let msg = intercepted_msg(&request.msg).unwrap();
                let value = match msg.name.as_str() {
                    "space_id" => Value::Bytes(space_id.to_vec()),
                    "peer_role" => Value::U8(AUTH_ROLE_ADMIN),
                    "members" => {
                        let after = msg.args.get_bytes("after_key").unwrap();
                        let wanted = if after.is_empty() {
                            0
                        } else {
                            u16::from_be_bytes(after.try_into().unwrap()).saturating_add(1)
                        };
                        let page = crate::registry::MemberPage {
                            members: registry_rows
                                .iter()
                                .filter(|row| row.prefix == wanted)
                                .cloned()
                                .collect(),
                            next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                            next_key: Vec::new(),
                            more: false,
                        };
                        Value::Bytes(page.encode())
                    }
                    other => panic!("unexpected registry probe {other}"),
                };
                assert!(request.reply.send(encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &value.encode(),
                )));
            }
        });
        let service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        let replication_id = [0x73; 32];
        let (sidecar_tx, _sidecar_rx) = mpsc::sync_channel(1);
        let (quiescence_tx, quiescence_rx) = mpsc::sync_channel(1);
        let route = Arc::new(PrivateIngressRoute {
            tx: sidecar_tx,
            quiescence_tx,
            barrier: PrivateIngressBarrier::new(),
            production_trust_policy: None,
        });
        service
            .service_private_ingress_routes
            .write()
            .unwrap()
            .insert(replication_id, route.clone());
        let handler = Arc::new(ReplaceHandler(
            AtomicUsize::new(0),
            RaftStatusReply {
                present: true,
                role: RaftRole::Leader,
                current_term: 3,
                commit_index: 8,
                last_applied: 8,
                last_log_index: 8,
                members: vec![old_prefix, replacement_prefix],
                joint_old: None,
                active_config_index: Some(4),
                leader_hint: Some(old_prefix),
            },
        ));
        network.register_raft_handler(replication_id, handler.clone());
        *service.shared_network.lock().unwrap() = Some(network.clone());

        let follower_handler = ReplaceHandler(
            AtomicUsize::new(0),
            RaftStatusReply {
                role: RaftRole::Follower,
                leader_hint: None,
                ..handler.1.clone()
            },
        );
        assert_eq!(
            service.handle_raft_replace_voter(
                operator,
                operator,
                &replication_id,
                old_prefix,
                old,
                remote_replacement_prefix,
                remote_replacement,
                operation_epoch,
                remote_operator_signature,
                &follower_handler,
            ),
            RaftReplaceVoterResult::NotLeader { leader_hint: None },
            "a follower redirects before requiring its own direct route to the replacement",
        );

        assert_eq!(
            service.handle_raft_replace_voter(
                operator,
                operator,
                &replication_id,
                old_prefix,
                old,
                replacement_prefix,
                replacement,
                operation_epoch - 1,
                stale_operator_signature,
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::NotAuthorized,
            "an authorization from an older membership epoch cannot start a new transition",
        );

        assert_eq!(
            service.handle_raft_replace_voter(
                libp2p::PeerId::random(),
                operator,
                &replication_id,
                old_prefix,
                old,
                replacement_prefix,
                replacement,
                operation_epoch,
                operator_signature,
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::NotAuthorized,
            "only the operator itself or an exact current-voter proxy may carry the request",
        );

        assert_eq!(
            service.handle_raft_replace_voter(
                old,
                operator,
                &replication_id,
                old_prefix,
                old,
                replacement_prefix,
                replacement,
                operation_epoch,
                [0u8; 64],
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::NotAuthorized,
            "a current voter cannot claim a known admin without that admin's signature",
        );

        assert_eq!(
            service.handle_raft_replace_voter(
                operator,
                operator,
                &replication_id,
                old_prefix,
                replacement,
                replacement_prefix,
                old,
                operation_epoch,
                operator_signature,
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::NotAuthorized,
            "the operator signature binds both complete identities and slots",
        );

        let admission = route.barrier.try_acquire().unwrap();
        assert_eq!(
            service.handle_raft_replace_voter(
                operator,
                operator,
                &replication_id,
                old_prefix,
                old,
                replacement_prefix,
                replacement,
                operation_epoch,
                operator_signature,
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::Busy,
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        drop(admission);

        let quiescence = thread::spawn(move || {
            quiescence_rx.recv().unwrap().send(true).unwrap();
        });
        assert_eq!(
            service.handle_raft_replace_voter(
                operator,
                operator,
                &replication_id,
                old_prefix,
                old,
                replacement_prefix,
                replacement,
                operation_epoch,
                operator_signature,
                handler.as_ref(),
            ),
            RaftReplaceVoterResult::Accepted { joint_index: 12 },
        );
        quiescence.join().unwrap();
        assert_eq!(handler.0.load(Ordering::Relaxed), 1);
        *service.shared_network.lock().unwrap() = None;
        drop(service);
        registry.join().unwrap();
        Arc::try_unwrap(network).ok().unwrap().join();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn crdt_replica_authority_binds_the_full_enrolled_peer_id() {
        use crate::actors::codec::Encode;
        use crate::value::Value;

        let enrolled = libp2p::PeerId::random();
        let attacker = libp2p::PeerId::random();
        let attacker_prefix = crate::network::derive_node_prefix(&attacker);
        let row = crate::registry::MemberRow {
            kind: crate::registry::MEMBER_KIND_NODE,
            key: enrolled.to_bytes(),
            // Model the exact row selected by the attacker's compact route.
            // Only the complete key comparison is allowed to reject it.
            prefix: attacker_prefix,
            role: crate::registry::NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let registry = thread::spawn(move || {
            let request = rx.recv().unwrap();
            let page = crate::registry::MemberPage {
                members: vec![row],
                next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: true,
            };
            assert!(request.reply.send(encode_invoke_envelope(
                crate::STATUS_DONE,
                &[],
                &Value::Bytes(page.encode()).encode(),
            )));
        });
        assert!(
            authenticated_service_crdt_replica_peer(
                &routes,
                &attacker.to_bytes(),
                Duration::from_secs(1),
            )
            .is_none(),
            "a prefix-selected row never authenticates a different Noise peer",
        );
        registry.join().unwrap();
    }

    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn authenticated_raft_delegation_performs_only_the_voter_registry_probe() {
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::run::STATUS_DONE;
        use crate::network::{
            Network, NetworkConfig, NetworkService, RaftAppendResult, RaftEntry, RaftRole,
            RaftRpcHandler, RaftStatusReply, RaftVoteResult,
        };
        use crate::registry::{MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberPage, MemberRow};
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        struct StatusHandler {
            voter: u16,
        }

        impl RaftRpcHandler for StatusHandler {
            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                _prev_log_term: u64,
                _leader_commit: u64,
                _entries: Vec<RaftEntry>,
            ) -> RaftAppendResult {
                RaftAppendResult {
                    term,
                    success: false,
                    match_index: prev_log_index,
                }
            }

            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                _from_prefix: u16,
                term: u64,
                _last_log_index: u64,
                _last_log_term: u64,
            ) -> RaftVoteResult {
                RaftVoteResult {
                    term,
                    vote_granted: false,
                }
            }

            fn handle_status(&self, _replication_id: &[u8; 32]) -> RaftStatusReply {
                RaftStatusReply {
                    present: true,
                    role: RaftRole::Leader,
                    current_term: 1,
                    commit_index: 1,
                    last_applied: 1,
                    last_log_index: 1,
                    members: vec![self.voter],
                    joint_old: None,
                    active_config_index: Some(1),
                    leader_hint: Some(self.voter),
                }
            }
        }

        let voter = libp2p::PeerId::random();
        let voter_prefix = crate::network::derive_node_prefix(&voter);
        let replication_id = [0xA4; 32];
        let target = ServiceId::new(0xCAFE, 0x0444);
        let target_name = "raft-public-root";

        let network_key = libp2p::identity::Keypair::generate_ed25519();
        let network_peer = libp2p::PeerId::from(network_key.public());
        let network = Arc::new(Network::start(NetworkConfig {
            keypair: network_key,
            local_prefix: crate::network::derive_node_prefix(&network_peer),
            listen: Vec::new(),
            bootstrap: Vec::new(),
            auto_dial_mdns: false,
        }));
        network.register_raft_handler(
            replication_id,
            Arc::new(StatusHandler {
                voter: voter_prefix,
            }),
        );

        let probes = Arc::new(Mutex::new(Vec::<String>::new()));
        let probes_for_registry = probes.clone();
        let (registry_tx, registry_rx) = mpsc::channel::<InvokeRequest>();
        let voter_bytes = voter.to_bytes();
        let registry = thread::spawn(move || {
            while let Ok(request) = registry_rx.recv() {
                let message = Msg::try_decode(&request.msg[1..]).expect("registry probe decodes");
                probes_for_registry
                    .lock()
                    .unwrap()
                    .push(message.name.clone());
                let value = if message.name == "members" {
                    Value::Bytes(
                        MemberPage {
                            members: vec![MemberRow {
                                kind: MEMBER_KIND_NODE,
                                key: voter_bytes.clone(),
                                prefix: voter_prefix,
                                role: crate::registry::NODE_ROLE_VOTER,
                                proof_kind: 0,
                                proof_data: Vec::new(),
                            }],
                            next_kind: MEMBER_KIND_IDENTITY,
                            next_key: Vec::new(),
                            more: false,
                        }
                        .encode(),
                    )
                } else {
                    // A regression would issue peer_role and actor_role here.
                    // Answer promptly so the assertion reports the exact
                    // redundant probes instead of making the test sleep 10 s.
                    Value::U8(AUTH_ROLE_ADMIN)
                };
                let _ =
                    request
                        .reply
                        .send(encode_invoke_envelope(STATUS_DONE, &[], &value.encode()));
            }
        });

        let (target_tx, target_rx) = mpsc::channel::<InvokeRequest>();
        let target_thread = thread::spawn(move || {
            let request = target_rx.recv().expect("delegated request reaches root");
            assert_eq!(request.space_role, None);
            assert_eq!(request.actor_local_role, None);
            assert_eq!(
                request.delegated_origin,
                Some(crate::service::Origin::System)
            );
            let _ = request.reply.send(encode_invoke_envelope(
                STATUS_DONE,
                &[],
                &Value::Unit.encode(),
            ));
        });

        let routes = Arc::new(Mutex::new(HashMap::from([
            (ServiceId::REGISTRY.0, registry_tx),
            (target.0, target_tx),
        ])));
        let mut service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        );
        service.service_actor_routes.write().unwrap().insert(
            crate::service::ActorId([0xA5; 32]),
            ActorRoute {
                route: target.0,
                service: crate::service::ServiceIdentity {
                    space: crate::service::SpaceId([0xA6; 32]),
                    root_service: crate::service::RootServiceId([0xA7; 32]),
                    deployment: crate::service::DeploymentId([0xA8; 32]),
                    service_program: crate::service::VOS_SERVICE_PROGRAM_ID,
                    platform: crate::service::PLATFORM_ID,
                    execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
                    gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
                },
                consistency: crate::service::ConsistencyMode::Raft,
                replication_id: Some(replication_id),
                is_role_authority: false,
                invoke_timeout: service_raft_invoke_timeout(5_000),
                authenticated_peer: None,
            },
        );
        service.agent_names = Arc::new(RwLock::new(HashMap::from([(
            local_id_of(target.0),
            target_name.to_string(),
        )])));
        service
            .raft_hosts
            .lock()
            .unwrap()
            .insert(target.0, replication_id);
        service.shared_network = Arc::new(Mutex::new(Some(network.clone())));
        service.sync_floor_cache.write().unwrap().insert(
            target_name.to_string(),
            (crate::registry::SyncFloor::Public, Instant::now()),
        );

        let mut ingress = vec![TAG_DYNAMIC];
        ingress.extend_from_slice(&Msg::new("start").encode());
        let delegated = encode_service_raft_delegation(
            crate::service::Origin::System,
            true,
            false,
            false,
            &ingress,
        );
        let reply = service.dispatch_invoke(Some(voter), 0, target.0, Vec::new(), delegated);
        assert!(!reply.is_empty());
        assert_eq!(
            probes.lock().unwrap().as_slice(),
            &["members".to_string()],
            "authenticated delegation probes the voter once and never probes irrelevant host roles",
        );

        drop(service);
        registry.join().unwrap();
        target_thread.join().unwrap();
        if let Ok(network) = Arc::try_unwrap(network) {
            network.join();
        }
    }

    /// A stub registry on route 0 that answers the `peer_role` probe with a
    /// fixed role byte — so the lifecycle interceptor's `lookup_caller_role`
    /// gate sees a known grant. Returns (routes, join handle).
    #[cfg(feature = "network")]
    fn spawn_stub_peer_role_registry(role: u8) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::value::Value;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let reply = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &Value::U8(role).encode(),
                );
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    #[cfg(feature = "network")]
    fn stub_enrolled_members(peer: Option<libp2p::PeerId>) -> crate::value::Value {
        use crate::actors::codec::Encode;
        crate::value::Value::Bytes(
            crate::registry::MemberPage {
                members: peer
                    .map(|peer| crate::registry::MemberRow {
                        kind: crate::registry::MEMBER_KIND_NODE,
                        key: peer.to_bytes(),
                        prefix: crate::network::derive_node_prefix(&peer),
                        role: crate::registry::NODE_ROLE_VOTER,
                        proof_kind: 0,
                        proof_data: Vec::new(),
                    })
                    .into_iter()
                    .collect(),
                next_kind: crate::registry::MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: false,
            }
            .encode(),
        )
    }

    /// Model grants independently from full authenticated node enrollment.
    #[cfg(feature = "network")]
    fn spawn_stub_role_registry(
        peer_role: u8,
        enrolled_peer: Option<libp2p::PeerId>,
    ) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::value::Value;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let value = match intercepted_method_name(&req.msg).as_deref() {
                    Some("members") => stub_enrolled_members(enrolled_peer),
                    Some("peer_role") => Value::U8(peer_role),
                    other => panic!("unexpected registry probe: {other:?}"),
                };
                let reply =
                    encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &value.encode());
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    fn spawn_stub_sync_floor_registry(
        floor: Option<crate::registry::SyncFloor>,
        space_role: u8,
    ) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::registry::{AgentLookup, AgentRow, PublicationId, RegistryProtocol};
        use crate::service::InstallationId;
        use crate::value::Value;

        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let value = match intercepted_method_name(&req.msg).as_deref() {
                    Some("service_actor") => Value::Bytes(
                        AgentLookup {
                            protocol: RegistryProtocol::CURRENT,
                            row: floor.map(|sync_role| AgentRow {
                                instance_name: "private-board".into(),
                                installation_id: InstallationId([3; 32]),
                                revision: 0,
                                program_hash: [1; 32],
                                program_name: "board".into(),
                                program_publication_id: PublicationId::new([4; 32]),
                                replication_id: [2; 32],
                                consistency: Consistency::Crdt as u8,
                                network_reachable: true,
                                sync_role,
                            }),
                        }
                        .encode(),
                    ),
                    _ => Value::U8(space_role),
                };
                let reply =
                    encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &value.encode());
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    /// Role + catalog stub for the program-blob serving gate.
    #[cfg(feature = "network")]
    fn spawn_stub_blob_registry(
        peer_role: u8,
        enrolled_peer: Option<libp2p::PeerId>,
        authorized: bool,
    ) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::value::Value;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let value = match intercepted_method_name(&req.msg).as_deref() {
                    Some("members") => stub_enrolled_members(enrolled_peer),
                    Some("program_blob_authorized") => Value::Bytes(
                        crate::registry::ProgramBlobAuthorization {
                            protocol: crate::registry::RegistryProtocol::CURRENT,
                            authorized,
                        }
                        .encode(),
                    ),
                    Some("peer_role") => Value::U8(peer_role),
                    other => panic!("unexpected registry probe: {other:?}"),
                };
                let reply =
                    encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &value.encode());
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    /// The `Member` sync floor admits a peer that holds a space read grant
    /// OR is an enrolled node (a voter/observer is a space member) — the
    /// latter unwedges the join→sync→grant bootstrap order. A stranger
    /// (no grant, not enrolled) and an anonymous caller are refused.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn sync_serve_allowed_member_admits_grants_and_enrolled_nodes() {
        use crate::registry::SyncFloor;
        let peer = libp2p::PeerId::random();
        let check = |peer_role: u8, enrolled_peer: Option<libp2p::PeerId>| -> bool {
            let (routes, _reg) = spawn_stub_role_registry(peer_role, enrolled_peer);
            let svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            // Seed the floor so resolve_sync_floor returns Member for the
            // app agent without an `agent()` probe against the stub.
            svc.sync_floor_cache
                .write()
                .unwrap()
                .insert("counter".to_string(), (SyncFloor::Member, Instant::now()));
            svc.sync_serve_allowed(Some(&peer), "counter")
        };
        assert!(
            !check(AUTH_ROLE_NONE, None),
            "a stranger is refused a Member replica"
        );
        assert!(
            check(AUTH_ROLE_READONLY, None),
            "a granted member is served"
        );
        assert!(
            check(AUTH_ROLE_NONE, Some(peer)),
            "an enrolled voter is served before a grant lands",
        );
        // Anonymous (no peer id) is refused for a non-Public floor.
        assert!(
            !check(AUTH_ROLE_NONE, Some(libp2p::PeerId::random())),
            "another node's enrollment does not authorize the caller",
        );
        let (routes, _reg) = spawn_stub_role_registry(AUTH_ROLE_READONLY, Some(peer));
        let svc = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        svc.sync_floor_cache
            .write()
            .unwrap()
            .insert("counter".to_string(), (SyncFloor::Member, Instant::now()));
        assert!(
            !svc.sync_serve_allowed(None, "counter"),
            "anonymous is refused Member"
        );
    }

    /// Program blobs require both space membership and a retained registry
    /// authorization, including displaced historical publications.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn get_program_blob_requires_member_and_authorized_hash() {
        use crate::network::NetworkService;
        // A temp dir standing in for vosx's content-addressed blob cache,
        // holding one ELF keyed by its hex hash (the layout the node reads).
        let dir = std::env::temp_dir().join(format!(
            "vos-progblob-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = b"\x7fELF fake actor body".to_vec();
        let hash = crate::crypto::blake2b_hash::<32>(&[], &[&bytes]);
        std::fs::write(dir.join(proof_blob_filename(&hash)), &bytes).unwrap();

        let peer = libp2p::PeerId::random();
        let make = |peer_role, enrolled_peer, authorized| {
            let (routes, _reg) = spawn_stub_blob_registry(peer_role, enrolled_peer, authorized);
            let mut svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            svc.program_blobs_dir = Some(dir.clone());
            svc
        };

        let member = make(AUTH_ROLE_READONLY, None, true);
        assert_eq!(
            member
                .get_program_blob(Some(libp2p::PeerId::random()), &hash)
                .as_deref(),
            Some(bytes.as_slice()),
            "a member gets an authorized ELF",
        );
        let enrolled = make(AUTH_ROLE_NONE, Some(peer), true);
        assert_eq!(
            enrolled.get_program_blob(Some(peer), &hash).as_deref(),
            Some(bytes.as_slice()),
            "an enrolled node gets an authorized ELF",
        );
        assert!(
            enrolled
                .get_program_blob(Some(libp2p::PeerId::random()), &hash)
                .is_none(),
            "another peer cannot borrow the enrolled node's access",
        );
        assert!(
            make(AUTH_ROLE_NONE, None, true)
                .get_program_blob(Some(libp2p::PeerId::random()), &hash)
                .is_none(),
            "a stranger is refused",
        );
        assert!(
            member.get_program_blob(None, &hash).is_none(),
            "an anonymous caller is refused",
        );
        assert!(
            make(AUTH_ROLE_READONLY, None, false)
                .get_program_blob(Some(libp2p::PeerId::random()), &hash)
                .is_none(),
            "an unauthorized hash is refused even when cached",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(feature = "network")]
    fn redeem_invite_expiry_is_checked_at_admission_boundary() {
        use crate::actors::codec::Encode;
        use crate::service::ServiceWire;
        use crate::value::{Msg, TAG_DYNAMIC};
        let before = Msg::new("redeem_invite").with("expires_at", 101u64);
        let boundary = Msg::new("redeem_invite").with("expires_at", 100u64);
        let malformed = Msg::new("redeem_invite");
        assert!(!redeem_invite_is_expired(&before, Some(100)));
        assert!(redeem_invite_is_expired(&boundary, Some(100)));
        assert!(redeem_invite_is_expired(&malformed, Some(100)));
        assert!(
            redeem_invite_is_expired(&before, None),
            "clock failure denies"
        );
        assert!(!redeem_invite_is_expired(&Msg::new("programs"), Some(100)));

        let redemption = crate::service::RoleAuthorityInviteRedemption {
            space: crate::service::SpaceId([1; 32]),
            authority_replication_id: [10; 32],
            token_pub: [2; 32],
            role: crate::SpaceRole::Member,
            expires_at: 101,
            admin_peer_id: vec![3; 38],
            admin_signature: [4; 64],
            holder_peer_id: vec![5; 38],
            redeem_signature: [6; 64],
            holder_signature: [7; 64],
        };
        let mut arguments = vec![TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new(crate::service::ROLE_AUTHORITY_INVITE_METHOD_)
                .with("redemption", redemption.encode())
                .encode(),
        );
        let invocation = crate::service::RootTreeInvocation {
            invocation: crate::service::InvocationId([8; 32]),
            target: crate::service::ActorId([9; 32]),
            method: crate::service::ROLE_AUTHORITY_INVITE_METHOD_.into(),
            arguments,
            proof_requested: false,
        };
        assert!(!authority_invite_is_expired(
            &invocation.encode(),
            Some(100)
        ));
        assert!(authority_invite_is_expired(&invocation.encode(), Some(101)));
        assert!(authority_invite_is_expired(&invocation.encode(), None));
    }

    #[cfg(feature = "network")]
    fn lifecycle_service(
        routes: InvokeRoutes,
        shutdown: AgentShutdown,
        info: AgentInfos,
    ) -> NodeService {
        NodeService {
            invoke_routes: routes,
            service_actor_routes: Arc::new(RwLock::new(HashMap::new())),
            agent_names: Arc::new(std::sync::RwLock::new(HashMap::new())),
            agent_shutdown: shutdown,
            agent_info: info,
            #[cfg(feature = "storage")]
            replicas: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "storage")]
            raft_hosts: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "storage")]
            service_private_ingress_routes: Arc::new(RwLock::new(HashMap::new())),
            shared_network: Arc::new(Mutex::new(None)),
            manifest: Arc::new(OnceLock::new()),
            proof_blobs: Arc::new(RwLock::new(HashMap::new())),
            proof_blobs_dir: None,
            program_blobs_dir: None,
            operator_peer: None,
            operator_signer: None,
            #[cfg(feature = "storage")]
            sync_floor_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "network")]
    #[test]
    fn catalog_ingress_binds_author_and_preserves_exact_payload() {
        use crate::actors::codec::Encode;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let author_key = libp2p::identity::Keypair::generate_ed25519();
        let author = libp2p::PeerId::from(author_key.public());
        let other = libp2p::PeerId::random();
        let author_bytes = author.to_bytes();
        let auth = crate::registry::pack_auth(&author_bytes, &[0xA5; crate::registry::OP_SIG_LEN]);
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(
            &Msg::new("unpublish_service_program")
                .with("name", "mailbox")
                .with("expected_publication_id", vec![0xB1_u8; 32])
                .with("expected_hash", vec![0xB2_u8; 32])
                .with("auth", auth)
                .encode(),
        );

        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let expected = payload.clone();
        let registry = thread::spawn(move || {
            loop {
                let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
                let decoded = intercepted_msg(&request.msg).unwrap();
                if decoded.name == "peer_role" {
                    let reply = Value::U8(AUTH_ROLE_ADMIN).encode();
                    assert!(request.reply.send(encode_invoke_envelope(
                        crate::STATUS_DONE,
                        &[],
                        &reply,
                    )));
                    continue;
                }
                assert_eq!(decoded.name, "unpublish_service_program");
                assert_eq!(request.msg, expected, "host must not rewrite signed bytes");
                assert!(request.reply.send(encode_invoke_envelope(
                    crate::STATUS_DONE,
                    &[],
                    b"accepted",
                )));
                break;
            }
        });
        let service = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );

        let rejected = service.dispatch_invoke(
            Some(other),
            0,
            ServiceId::REGISTRY.0,
            vec![],
            payload.clone(),
        );
        assert_eq!(rejected, forbidden_envelope());
        assert_eq!(
            service.dispatch_invoke(Some(author), 0, ServiceId::REGISTRY.0, vec![], payload,),
            b"accepted",
        );
        registry.join().unwrap();
    }

    #[cfg(feature = "network")]
    #[test]
    fn catalog_ingress_matches_authenticated_delegated_member_only() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(key.public());
        let signer = peer.to_bytes();
        let subject = crate::service::SubjectId::of_authenticated_peer(&signer);
        let forwarder = libp2p::PeerId::random();

        assert!(catalog_author_matches_ingress(&signer, Some(&peer), None));
        assert!(!catalog_author_matches_ingress(
            &signer,
            Some(&forwarder),
            None,
        ));
        assert!(catalog_author_matches_ingress(
            &signer,
            Some(&forwarder),
            Some(crate::service::Origin::Member(subject)),
        ));
        assert!(!catalog_author_matches_ingress(
            &signer,
            Some(&peer),
            Some(crate::service::Origin::Member(crate::service::SubjectId(
                [0x55; 32]
            ),)),
        ));
        for origin in [
            crate::service::Origin::Anonymous,
            crate::service::Origin::Actor(crate::service::ActorId([0x66; 32])),
            crate::service::Origin::System,
        ] {
            assert!(!catalog_author_matches_ingress(
                &signer,
                Some(&peer),
                Some(origin),
            ));
        }
    }

    /// The node-level `__stop` / `__describe`
    /// interceptor answers those reserved wire methods host-side — for an
    /// agent with **no invoke route** — when the caller is authorized (ADMIN for stop, member for
    /// describe). `__describe` returns the JSON snapshot; `__stop` flips the
    /// agent's shutdown flag and replies Unit.
    #[cfg(feature = "network")]
    #[test]
    fn lifecycle_interceptor_admin_stops_and_describes() {
        use crate::actors::codec::{Decode, Encode};
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0123);
        let flag = Arc::new(AtomicBool::new(false));
        let shutdown: AgentShutdown =
            Arc::new(Mutex::new(HashMap::from([(target.0, flag.clone())])));
        let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("worker".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));

        // Registry grants this peer ADMIN. NOTE: the target itself has NO
        // route — the interceptor must answer before the route lookup.
        let (routes, reg) = spawn_stub_peer_role_registry(AUTH_ROLE_ADMIN);
        let service = lifecycle_service(routes, shutdown, info);
        let peer = libp2p::PeerId::random();

        // __describe → rkyv Value::Str(json) with the live running flag.
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("__describe").encode());
        let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
        let json = match <Value as Decode>::decode(&reply) {
            Value::Str(s) => s,
            other => panic!("__describe should reply Value::Str, got {other:?}"),
        };
        assert!(
            json.contains("\"name\":\"worker\"") && json.contains("\"running\":true"),
            "describe json: {json}",
        );

        // __stop → empty reply (Unit) + flag flipped.
        assert!(!flag.load(Ordering::Relaxed));
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("__stop").encode());
        let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
        assert!(
            reply.is_empty(),
            "__stop replies empty (Value::Unit → null)"
        );
        assert!(
            flag.load(Ordering::Relaxed),
            "__stop must flip the agent's shutdown flag",
        );

        drop(service);
        reg.join().unwrap();
    }

    /// A non-admin / non-member caller is REFUSED —
    /// `__stop`/`__describe` return a `STATUS_FORBIDDEN` envelope and the
    /// agent's shutdown flag is NOT touched. Closes the "any dialable peer
    /// can stop/enumerate any agent" hole.
    #[cfg(feature = "network")]
    #[test]
    fn lifecycle_interceptor_refuses_non_member() {
        use crate::actors::codec::Encode;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC};

        let target = ServiceId::new(0x00ab, 0x0123);
        let flag = Arc::new(AtomicBool::new(false));
        let shutdown: AgentShutdown =
            Arc::new(Mutex::new(HashMap::from([(target.0, flag.clone())])));
        let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("worker".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));

        // Registry grants this peer NO role (non-member).
        let (routes, reg) = spawn_stub_peer_role_registry(AUTH_ROLE_NONE);
        let service = lifecycle_service(routes, shutdown, info);
        let peer = libp2p::PeerId::random();

        for method in ["__stop", "__describe"] {
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new(method).encode());
            let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
            assert_eq!(
                reply.first().copied(),
                Some(crate::actors::run::STATUS_FORBIDDEN),
                "{method} from a non-member must return a STATUS_FORBIDDEN envelope",
            );
        }
        assert!(
            !flag.load(Ordering::Relaxed),
            "a refused __stop must NOT flip the shutdown flag",
        );

        drop(service);
        reg.join().unwrap();
    }

    /// A3 — commit-then-outbox: a dispatch that produces an external
    /// transfer must route it only after the commit succeeds. A failed
    /// commit routes nothing (no leak); a subsequent successful attempt
    /// routes exactly once (the failed attempt did not duplicate).
    #[test]
    #[ignore = "requires the compiled probe fixture; run just check-probe-fixture"]
    fn dispatch_routes_external_transfers_only_after_commit() {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        use std::sync::mpsc;

        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(|target| fixture.join(target))
            .unwrap_or_else(|| fixture.join("target"));
        let elf_path = target.join("riscv64em-vos/release/probe.elf");
        let elf = std::fs::read(&elf_path).unwrap_or_else(|error| {
            panic!(
                "read probe ELF {}: {error}; run just check-probe-fixture",
                elf_path.display()
            )
        });
        let blob = vos_pvm_compiler::link_elf(&elf).expect("probe transpiles");

        let mut runtime = VosRuntime::new();
        let blob_idx = runtime.register_service_blob(blob);
        let probe = runtime.register_service(blob_idx);

        // A tell to a service this runtime does not host is an external
        // transfer routed through the node's outbox.
        let external_target = ServiceId(0xEE00);
        let tell = {
            let enc = Msg::new("tell_out")
                .with("target", external_target.0)
                .encode();
            let mut m = vec![TAG_DYNAMIC];
            m.extend_from_slice(&enc);
            m
        };

        let (tx, rx) = mpsc::channel::<Envelope>();

        struct FailCommit;
        impl crate::commit::CommitStrategy for FailCommit {
            fn restore(&mut self) -> Option<Vec<u8>> {
                None
            }
            fn commit(
                &mut self,
                _delta: &crate::commit::AgentDelta<'_>,
            ) -> Result<crate::commit::CommitReceipt, crate::commit::CommitError> {
                Err(crate::commit::CommitError::Config(
                    "forced commit failure".into(),
                ))
            }
        }

        // First attempt: the commit fails, so nothing may be routed.
        let mut fail = FailCommit;
        let r = dispatch_once(
            &mut runtime,
            probe,
            &tx,
            probe,
            Some(tell.clone()),
            &mut fail,
            false,
        );
        assert!(
            r.is_err(),
            "the failing strategy must surface its commit error"
        );
        assert!(
            rx.try_recv().is_err(),
            "a failed commit must route no external transfer"
        );

        // Retry with a strategy that commits: the transfer routes once.
        let mut ok = crate::commit::NoCommit;
        let r = dispatch_once(&mut runtime, probe, &tx, probe, Some(tell), &mut ok, false);
        assert!(r.is_ok(), "the succeeding strategy must commit");
        let env = rx
            .try_recv()
            .expect("a committed dispatch routes its external transfer");
        assert_eq!(env.to, external_target);
        assert!(
            rx.try_recv().is_err(),
            "exactly one transfer routed — the failed attempt left nothing to duplicate"
        );
    }
}
