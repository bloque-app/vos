//! Preparation of an exact signed Local Create request for the native operator.
//!
//! Sequence allocation and durable request-file publication belong to the
//! caller. Preparation never reads a clock, generates a nonce, loads a key, or
//! submits a request: retries must reuse the persisted image-format LCQ1 bytes.

use std::num::NonZeroU64;

use libp2p::identity::Keypair;
use vos::agent::local_lifecycle::LocalCreateSubmission;
use vos::agent::package_admission::AdmittedRuntimePackage;
use vos::agent::sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget,
};
use vos::agent::sdk::{AgentDescriptor, InvocationId, ManagementRequest};

use super::clean_identity::CleanOperatorIdentitySigner;

pub(crate) fn run_create(
    query: &str,
    http: Option<std::net::SocketAddr>,
    resume: bool,
) -> anyhow::Result<()> {
    let (data, space, public, address) = resolve_local_space(query, http)?;
    let operator = crate::identity::load_existing()?;
    let ack = create_local(&data, address, &operator, space, public, resume)?;
    print_acknowledgement(&ack)
}

pub(super) fn resolve_local_space(
    query: &str,
    http: Option<std::net::SocketAddr>,
) -> anyhow::Result<(
    std::path::PathBuf,
    vos::agent::sdk::SpaceId,
    [u8; 32],
    std::net::SocketAddr,
)> {
    let index = crate::spaces_index::load()?;
    let entry = crate::spaces_index::find(&index, query)?;
    let data = std::path::Path::new(&entry.data_dir);
    let space = vos::agent::sdk::SpaceId(
        hex::decode(&entry.id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Space ID"))?,
    );
    let endpoint = super::endpoint::read(data)?
        .ok_or_else(|| anyhow::anyhow!("start the space before managing a Local Agent"))?;
    anyhow::ensure!(
        super::endpoint::is_alive(&endpoint),
        "space daemon is not running"
    );
    let peer: libp2p::PeerId = endpoint.peer_id.parse()?;
    let public = vos::registry::ed25519_pubkey_from_peer_id(&peer.to_bytes())
        .ok_or_else(|| anyhow::anyhow!("daemon must advertise a full Ed25519 peer identity"))?;
    let address = match http {
        Some(address) => address,
        None => {
            let config = super::local_config::load(data)?;
            let listeners = config
                .ingress
                .http
                .iter()
                .filter(|listener| listener.tls_cert.is_none() && listener.tls_key.is_none())
                .filter_map(|listener| listener.listen.parse::<std::net::SocketAddr>().ok())
                .filter(|address| address.ip().is_loopback() && address.port() != 0)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                listeners.len() == 1,
                "specify --http with one local plaintext daemon endpoint"
            );
            listeners[0]
        }
    };
    Ok((data.to_path_buf(), space, public, address))
}

/// Create an operator-owned ordinary Shared Agent whose single voter is this
/// node. Shares Local Create's credential lease and exact-retry discipline.
pub(crate) fn run_create_shared(
    query: &str,
    http: Option<std::net::SocketAddr>,
    resume: bool,
) -> anyhow::Result<()> {
    let (data, space, public, address) = resolve_local_space(query, http)?;
    let operator = crate::identity::load_existing()?;
    let ack = create_agent(&data, address, &operator, space, public, resume, true)?;
    let agent = hex::encode(ack.managed.agent.0);
    if crate::output::is_json() {
        print_acknowledgement(&ack)
    } else {
        println!("Shared Agent {agent}: verified creation acknowledgement");
        Ok(())
    }
}

/// The credential lease spans every phase. Existing request bytes always take
/// precedence over discovery and preparation when explicitly resuming.
pub(crate) fn create_local(
    data: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    resume: bool,
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    create_agent(data, address, operator, space, node_public, resume, false)
}

fn create_agent(
    data: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    resume: bool,
    shared: bool,
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    use super::clean_store::{
        CleanCredentialReservation, CleanLocalCreateRequestFile, CredentialReservationStatus,
        ensure_private_directory,
    };
    use vos::agent::sdk::{Hash, wire::CanonicalWire as _};
    let started = std::time::Instant::now();
    let storage = super::local_config::load(data)?.local_agent_storage;
    super::local_config::validate_local_storage_roots(data, storage)?;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "Local Create requires a nonzero loopback endpoint"
    );
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_storage(storage)?,
        "system-authority",
        operator,
    )?;
    let (authority, _) = super::clean_startup::derive_system_authority_target(
        space,
        identity.raw_public_key(),
        &runtime,
        &authority_package,
    )?;
    let root = data.join("agent-client");
    let _root = ensure_private_directory(&root)?;
    let claims = root.join("credentials");
    let _claims = ensure_private_directory(&claims)?;
    let mut reservation =
        CleanCredentialReservation::open_or_create(&claims, space, identity.credential())?;
    let current = reservation.current()?;
    let nonce = match current {
        Some((nonce, _)) if resume => nonce,
        Some((nonce, CredentialReservationStatus::Pending)) => anyhow::bail!(
            "Local Create {} is pending; use --resume",
            hex::encode(nonce.0)
        ),
        _ if resume => anyhow::bail!("no Local Create operation to resume"),
        _ => {
            let mut bytes = [0; 32];
            getrandom::getrandom(&mut bytes)
                .map_err(|error| anyhow::anyhow!("operation nonce entropy: {error}"))?;
            anyhow::ensure!(bytes != [0; 32], "operation nonce entropy was zero");
            Hash(bytes)
        }
    };
    let status = reservation.reserve(nonce)?;
    let operations = root.join("operations");
    let _operations = ensure_private_directory(&operations)?;
    let operation = operations.join(format!(
        "{}-{}",
        hex::encode(identity.credential().0),
        hex::encode(nonce.0)
    ));
    let _operation = ensure_private_directory(&operation)?;
    let request_root = operation.join("request");
    let mut store = CleanLocalCreateRequestFile::open_or_create(&request_root)?;
    let bytes = match store.load()? {
        Some(bytes) => bytes,
        None => {
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "completed operation is missing its retained request"
            );
            let (_, sequence) =
                discover_credential(&operation.join("query"), address, operator, authority)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expires = now
                .checked_add(3600)
                .ok_or_else(|| anyhow::anyhow!("validity window overflow"))?;
            let bytes = if shared {
                prepare_fresh_shared(
                    operator,
                    space,
                    node_public,
                    nonce,
                    sequence,
                    now.saturating_sub(60),
                    expires,
                )?
                .encode()
            } else {
                prepare_fresh(
                    operator,
                    space,
                    node_public,
                    nonce,
                    sequence,
                    now.saturating_sub(60),
                    expires,
                )?
                .encode()
            };
            store.publish(&bytes)?;
            bytes
        }
    };
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        retained_bytes = bytes.len(),
        "Local Create request ready",
    );
    anyhow::ensure!(
        bytes.starts_with(if shared { b"SCQ1" } else { b"LCQ1" }),
        "retained Create {} has a different Agent profile; resume it with its original command",
        hex::encode(nonce.0)
    );
    let (descriptor, call) = decode_retained_request(&bytes)?;
    anyhow::ensure!(
        descriptor.creation_nonce == nonce
            && descriptor.identity.space == space
            && descriptor.identity.owner == identity.principal()
            && call.principal == identity.principal()
            && call.credential == identity.credential()
            && call.authority == authority
            && descriptor.identity.transition_producer
                == vos::agent::sdk::ProducerId::of_public_key(&node_public),
        "retained Create differs from the selected Space, operator or node"
    );
    drop(store);
    let mut acknowledgement_store =
        super::clean_store::CleanLocalCreateAcknowledgementFile::open_or_create(
            operation.join("acknowledgement"),
            &bytes,
        )?;
    // Verify/re-sync any prior response, but continue exercising the server's
    // exact retry path. A saved response is not a live publication check.
    let saved_ack = acknowledgement_store.load()?;
    let mut denial_store = super::clean_store::CleanLocalCreateDenialFile::open_or_create(
        operation.join("denial"),
        &bytes,
    )?;
    if denial_store.load()?.is_some() {
        anyhow::ensure!(
            saved_ack.is_none(),
            "operation has conflicting completion evidence"
        );
        reservation.deny(&mut denial_store)?;
        anyhow::bail!(
            "Local Create was denied; signed denial retained. Start a new Create without --resume"
        );
    }
    anyhow::ensure!(
        status != CredentialReservationStatus::Denied,
        "denied operation is missing its retained certificate"
    );
    let submission_started = std::time::Instant::now();
    let ack = match submit_retained_disposition(&request_root, address)? {
        vos::agent::local_lifecycle::LocalCreateDisposition::Created(_, ack) => ack,
        vos::agent::local_lifecycle::LocalCreateDisposition::Denied(denial) => {
            anyhow::ensure!(
                saved_ack.is_none(),
                "operation has conflicting completion evidence"
            );
            denial_store.publish(denial.exact_bytes())?;
            reservation.deny(&mut denial_store)?;
            anyhow::bail!(
                "Local Create was denied; signed denial retained. Start a new Create without --resume"
            );
        }
    };
    tracing::debug!(
        elapsed_ms = submission_started.elapsed().as_millis() as u64,
        "Local Create verified daemon response",
    );
    let encoded = ack
        .encode()
        .map_err(|error| anyhow::anyhow!("encode acknowledgement: {error:?}"))?;
    // Completion must never outlive the verified response bytes it names.
    acknowledgement_store.publish(&encoded)?;
    reservation.complete(&bytes, &encoded)?;
    Ok(ack)
}

pub(super) fn post_binary(
    address: std::net::SocketAddr,
    path: &'static str,
    status: u16,
    bytes: &[u8],
    maximum: usize,
) -> anyhow::Result<Vec<u8>> {
    post_binary_response(address, path, status, bytes, maximum, None, None).map(|(_, bytes)| bytes)
}

pub(super) fn post_binary_authenticated(
    address: std::net::SocketAddr,
    path: &'static str,
    bytes: &[u8],
    maximum: usize,
    access_token: &str,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        vos::ingress::decode_access_token(access_token).is_some(),
        "invalid VOS access token"
    );
    post_binary_response(address, path, 200, bytes, maximum, None, Some(access_token))
        .map(|(_, bytes)| bytes)
}

pub(super) fn post_binary_response(
    address: std::net::SocketAddr,
    path: &'static str,
    status: u16,
    bytes: &[u8],
    maximum: usize,
    denial_maximum: Option<usize>,
    access_token: Option<&str>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    use std::io::Read as _;
    use std::time::Duration;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "plaintext Agent control requires a nonzero loopback address"
    );
    let request = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(130))
        .build()
        .post(&format!("http://{address}{path}"))
        .set("Content-Type", "application/octet-stream");
    let request = match access_token {
        Some(token) => request.set("Authorization", &format!("Bearer {token}")),
        None => request,
    };
    let response = request.send_bytes(bytes);
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(403, response)) if denial_maximum.is_some() => response,
        Err(error) => return Err(error.into()),
    };
    let actual_status = response.status();
    let maximum = if actual_status == 403 {
        denial_maximum.unwrap_or(maximum)
    } else {
        maximum
    };
    anyhow::ensure!(
        actual_status == status || (denial_maximum.is_some() && actual_status == 403),
        "Agent control expected HTTP {status}, received {}",
        response.status()
    );
    anyhow::ensure!(
        response.header("Content-Type") == Some("application/octet-stream"),
        "Agent control reply has unexpected content type"
    );
    let mut reply = Vec::new();
    response
        .into_reader()
        .take((maximum + 1) as u64)
        .read_to_end(&mut reply)?;
    anyhow::ensure!(
        reply.len() <= maximum,
        "Agent control reply exceeds the wire limit"
    );
    Ok((actual_status, reply))
}

pub(super) fn retained_submission_error(error: anyhow::Error) -> anyhow::Error {
    if matches!(
        error.downcast_ref::<ureq::Error>(),
        Some(ureq::Error::Status(409, _))
    ) {
        anyhow::anyhow!(
            "{error}; request retained: lifecycle conflicts with retained state; inspect operation evidence before retrying. HTTP conflict is not a signed outcome and does not prove the original operation failed"
        )
    } else {
        anyhow::anyhow!(
            "{error}; request retained: retry these exact bytes, outcome may be unknown"
        )
    }
}

pub(super) struct CredentialVerifier;
impl vos::agent::sdk::authority::AuthorityCredentialVerifier for CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        libp2p::identity::ed25519::PublicKey::try_from_bytes(public_key)
            .is_ok_and(|key| key.verify(message, signature))
    }
}

/// Query bytes must be retained by the caller before dispatch and reused after
/// ambiguity. This local response is a discovery hint, not signed finality or
/// a reservation: Authority still authorizes the subsequent exact mutation.
pub(crate) fn query_credential(
    address: std::net::SocketAddr,
    query_bytes: &[u8],
    expected_principal: vos::agent::sdk::PrincipalId,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    query_credential_for(
        address,
        query_bytes,
        expected_principal,
        CredentialSequenceDomain::Management,
    )
}

#[derive(Clone, Copy)]
enum CredentialSequenceDomain {
    Management,
    Operation,
    Admin,
}

fn query_credential_for(
    address: std::net::SocketAddr,
    query_bytes: &[u8],
    expected_principal: vos::agent::sdk::PrincipalId,
    domain: CredentialSequenceDomain,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    use vos::agent::sdk::authority::{AuthorityProjectionQuery, AuthorityProjectionSelector};
    use vos::agent::sdk::wire::{
        CanonicalWire as _, MAX_AUTHORITY_CREDENTIAL_PROJECTION_WIRE_BYTES,
    };
    let query = AuthorityProjectionQuery::decode(query_bytes)
        .map_err(|error| anyhow::anyhow!("invalid retained credential query: {error:?}"))?;
    query
        .verify_api_with(&CredentialVerifier)
        .map_err(|error| anyhow::anyhow!("invalid credential query signature: {error:?}"))?;
    anyhow::ensure!(
        query.selector == AuthorityProjectionSelector::Credential,
        "credential discovery requires the Credential selector"
    );
    let bytes = post_binary(
        address,
        "/__agents/credential",
        200,
        query_bytes,
        MAX_AUTHORITY_CREDENTIAL_PROJECTION_WIRE_BYTES,
    )
    .map_err(|error| anyhow::anyhow!("{error}; retry the identical retained credential query"))?;
    validate_credential_response_for(&query, expected_principal, &bytes, domain)
}

/// Persist a first query before sending, or resume the exact retained query.
/// The caller must also hold its credential-wide mutation reservation; this
/// per-query lease does not serialize other directories or other clients.
pub(crate) fn discover_credential(
    root: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    authority: AuthorityActorTarget,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    discover_credential_for(
        root,
        address,
        operator,
        authority,
        CredentialSequenceDomain::Management,
    )
}

/// Operation issuance has its own credential-local sequence domain. Caller
/// holds the credential reservation and must retain the resulting AOQ1 before
/// dispatch; discovery is neither sequence reservation nor policy approval.
pub(crate) fn discover_operation_credential(
    root: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    authority: AuthorityActorTarget,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    discover_credential_for(
        root,
        address,
        operator,
        authority,
        CredentialSequenceDomain::Operation,
    )
}

pub(crate) fn discover_admin_credential(
    root: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    authority: AuthorityActorTarget,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    discover_credential_for(
        root,
        address,
        operator,
        authority,
        CredentialSequenceDomain::Admin,
    )
}

fn discover_credential_for(
    root: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &Keypair,
    authority: AuthorityActorTarget,
    domain: CredentialSequenceDomain,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
    use vos::agent::sdk::authority::AuthorityProjectionSelector;
    use vos::agent::sdk::wire::CanonicalWire as _;
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    let mut store = super::clean_store::CleanCredentialQueryFile::open_or_create(
        root,
        authority,
        identity.credential(),
    )?;
    let bytes = match store.load()? {
        Some(bytes) => bytes,
        None => {
            let mut signer = super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(operator.clone())?;
            let query = signer.authenticate(authority, AuthorityProjectionSelector::Credential)?;
            let bytes = query
                .encode()
                .map_err(|error| anyhow::anyhow!("encode credential query: {error:?}"))?;
            store.publish(&bytes)?;
            bytes
        }
    };
    query_credential_for(address, &bytes, identity.principal(), domain)
}

fn validate_credential_response(
    query: &vos::agent::sdk::authority::AuthorityProjectionQuery,
    expected_principal: vos::agent::sdk::PrincipalId,
    bytes: &[u8],
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    validate_credential_response_for(
        query,
        expected_principal,
        bytes,
        CredentialSequenceDomain::Management,
    )
}

fn validate_credential_response_for(
    query: &vos::agent::sdk::authority::AuthorityProjectionQuery,
    expected_principal: vos::agent::sdk::PrincipalId,
    bytes: &[u8],
    domain: CredentialSequenceDomain,
) -> anyhow::Result<(
    vos::agent::sdk::authority::AuthorityCredentialProjection,
    NonZeroU64,
)> {
    use vos::agent::sdk::authority::{
        AuthorityCredentialKind, AuthorityCredentialProjection, AuthorityCredentialStatus,
    };
    use vos::agent::sdk::wire::CanonicalWire as _;
    let projection = AuthorityCredentialProjection::decode(bytes)
        .map_err(|error| anyhow::anyhow!("invalid credential response: {error:?}"))?;
    anyhow::ensure!(
        projection.query == *query && projection.principal == expected_principal,
        "credential response does not match the exact query and owner"
    );
    anyhow::ensure!(
        projection.status == AuthorityCredentialStatus::Active
            && projection.kind == AuthorityCredentialKind::Api,
        "credential discovery requires an active API credential"
    );
    let high_water = match domain {
        CredentialSequenceDomain::Management => projection.management_request_high_water,
        CredentialSequenceDomain::Operation => projection.operation_request_high_water,
        CredentialSequenceDomain::Admin => projection.admin_request_high_water,
    };
    let sequence = high_water
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or_else(|| anyhow::anyhow!("selected credential sequence domain exhausted"))?;
    Ok((projection, sequence))
}

/// Prepare against the same bundled root system identity used by startup.
/// The node's public key is sufficient; never load its private transport key.
/// The caller must discover/check live state and allocate sequence/nonce before
/// this call, then publish the resulting bytes before sending.
pub(crate) fn prepare_fresh(
    operator: &Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    nonce: vos::agent::sdk::Hash,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalCreateSubmission> {
    let (authority, descriptor, runtime) = fresh_descriptor(
        operator,
        space,
        node_public,
        nonce,
        vos::agent::sdk::AgentProfile::Local,
    )?;
    prepare(
        operator, authority, descriptor, runtime, sequence, valid_from, expires_at,
    )
}

/// Ordinary Shared Create whose single voter is this node, identified by its
/// advertised transport key. Endorsement and publication remain daemon-side.
pub(crate) fn prepare_fresh_shared(
    operator: &Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    nonce: vos::agent::sdk::Hash,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<vos::agent::local_lifecycle::SharedCreateSubmission> {
    use vos::agent::genesis::{AgentReplicaCommittee, AgentReplicaMember};
    let (authority, descriptor, runtime) = fresh_descriptor(
        operator,
        space,
        node_public,
        nonce,
        vos::agent::sdk::AgentProfile::Shared,
    )?;
    let node_key = libp2p::identity::ed25519::PublicKey::try_from_bytes(&node_public)
        .map_err(|_| anyhow::anyhow!("invalid node public key"))?;
    let peer = libp2p::identity::PublicKey::from(node_key)
        .to_peer_id()
        .to_bytes();
    let replica = &descriptor.replicas[0];
    let replicas = AgentReplicaCommittee::new(
        vos::service::SpaceId(space.0),
        vos::service::AgentId(descriptor.identity.agent.0),
        vos::agent::AgentProfile::Shared,
        vec![
            AgentReplicaMember::new(
                vos::agent::AgentReplica {
                    node: vos::service::NodeId(replica.node.0),
                    principal: vos::service::PrincipalId(replica.principal.0),
                    role: vos::agent::ReplicaRole::Voter,
                },
                peer.clone(),
                node_public,
                Some(vos::agent::genesis::derive_replica_raft_slot(&peer)),
            )
            .map_err(|error| anyhow::anyhow!("invalid replica member: {error:?}"))?,
        ],
    )
    .map_err(|error| anyhow::anyhow!("invalid replica committee: {error:?}"))?;
    let call = sign_create_call(
        operator,
        authority,
        &descriptor,
        sequence,
        valid_from,
        expires_at,
    )?;
    vos::agent::local_lifecycle::SharedCreateSubmission::new(descriptor, call, runtime, replicas)
        .map_err(|error| anyhow::anyhow!("invalid signed Shared Create: {error:?}"))
}

fn fresh_descriptor(
    operator: &Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    nonce: vos::agent::sdk::Hash,
    profile: vos::agent::sdk::AgentProfile,
) -> anyhow::Result<(
    AuthorityActorTarget,
    AgentDescriptor,
    AdmittedRuntimePackage,
)> {
    use vos::agent::sdk::{AgentId, AgentIdentity, AgentReplica, ProducerId, ReplicaRole};
    let signer = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        node_public != signer.raw_public_key(),
        "root and node identities must be distinct"
    );
    let node_key = libp2p::identity::ed25519::PublicKey::try_from_bytes(&node_public)
        .map_err(|_| anyhow::anyhow!("invalid node public key"))?;
    let node_peer = libp2p::identity::PublicKey::from(node_key).to_peer_id();
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        "system-authority",
        operator,
    )?;
    let (authority, _) = super::clean_startup::derive_system_authority_target(
        space,
        signer.raw_public_key(),
        &runtime,
        &authority_package,
    )?;
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent: AgentId::derive(space, signer.principal(), nonce.as_bytes()),
            owner: signer.principal(),
            profile,
            runtime_deployment: runtime.deployment(),
            runtime_program: runtime.program(),
            runtime_producer: runtime.producer(),
            transition_producer: ProducerId::of_public_key(&node_public),
        },
        creation_nonce: nonce,
        authority: authority.binding,
        private_recovery: None,
        runtime_package: runtime.package_ref().clone(),
        runtime_contract: runtime.manifest().contract,
        capabilities: runtime.capabilities(),
        replicas: vec![AgentReplica {
            node: super::clean_identity::node_id_from_authenticated_peer(&node_peer),
            principal: signer.principal(),
            role: ReplicaRole::Voter,
        }],
    };
    Ok((authority, descriptor, runtime))
}

/// Submit an already persisted request to a local daemon. No signing or
/// sequence allocation occurs here; every error leaves the request retained.
pub(crate) fn submit_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    match submit_retained_disposition(root, address)? {
        vos::agent::local_lifecycle::LocalCreateDisposition::Created(_, ack) => Ok(ack),
        vos::agent::local_lifecycle::LocalCreateDisposition::Denied(_) => {
            anyhow::bail!("verified Local Create denial; request retained")
        }
    }
}

fn submit_retained_disposition(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<vos::agent::local_lifecycle::LocalCreateDisposition> {
    use super::clean_store::CleanLocalCreateRequestFile;
    use vos::agent::local_lifecycle::LocalCreateDisposition;
    use vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "plaintext Local Create submission requires a nonzero loopback address"
    );
    let mut store = CleanLocalCreateRequestFile::open_or_create(root)?;
    let bytes = store
        .load()?
        .ok_or_else(|| anyhow::anyhow!("no retained Local Create request"))?;
    let shared = bytes.starts_with(b"SCQ1");
    let result = (|| -> anyhow::Result<_> {
        let (status, reply) = post_binary_response(
            address,
            if shared {
                "/__agents/shared"
            } else {
                "/__agents/local"
            },
            201,
            &bytes,
            MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
            (!shared).then_some(vos::agent::local_lifecycle::LocalCreateDenial::MAX_BYTES),
            None,
        )?;
        if status == 403 {
            let denial = verify_denial(&bytes, &reply)?;
            Ok(LocalCreateDisposition::Denied(denial))
        } else {
            let ack = verify_acknowledgement(&bytes, &reply)?;
            Ok(LocalCreateDisposition::Created(ack.managed.agent, ack))
        }
    })();
    // The store and its exclusive lease remain alive through verification.
    result.map_err(retained_submission_error)
}

pub(crate) fn run_submit(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let ack = submit_retained(root, address)?;
    print_acknowledgement(&ack)
}

fn print_acknowledgement(
    ack: &vos::agent::sdk::authority::ManagementApplicationAck,
) -> anyhow::Result<()> {
    use vos::agent::sdk::wire::CanonicalWire as _;
    let agent = hex::encode(ack.managed.agent.0);
    if crate::output::is_json() {
        crate::output::print_json(&serde_json::json!({
            "agent": agent,
            "acknowledgement": hex::encode(ack.encode().map_err(|error| anyhow::anyhow!("encode acknowledgement: {error:?}"))?),
        }));
    } else {
        println!("Local Agent {agent}: verified creation acknowledgement");
    }
    Ok(())
}

/// Verify a response against the retained request, never a key supplied only
/// by the response. This verifies the issuer's application claim, not an
/// independent replay proof or proof of HTTP route publication.
pub(crate) fn verify_acknowledgement(
    request: &[u8],
    response: &[u8],
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    let (_, call) = decode_retained_request(request)?;
    verify_call_acknowledgement(&call, response)
}

/// Authenticate the supported exact Create format. Retired external requests
/// remain on disk but are never submitted or reinterpreted as image requests.
pub(crate) fn decode_retained_request(
    request: &[u8],
) -> anyhow::Result<(AgentDescriptor, AuthorityCredentialCall)> {
    match request.get(..4) {
        Some(b"LCQ1") => {
            let (descriptor, call, _) = LocalCreateSubmission::decode(request)
                .map_err(|error| anyhow::anyhow!("invalid retained LCQ1: {error:?}"))?
                .into_parts();
            Ok((descriptor, call))
        }
        Some(b"SCQ1") => {
            let (descriptor, call, _, _) =
                vos::agent::local_lifecycle::SharedCreateSubmission::decode(request)
                    .map_err(|error| anyhow::anyhow!("invalid retained SCQ1: {error:?}"))?
                    .into_parts();
            Ok((descriptor, call))
        }
        Some(b"LCQ2") => anyhow::bail!(
            "external-state Local Create is unsupported; preserve the retained request"
        ),
        _ => anyhow::bail!("unrecognized Local Create request format"),
    }
}

pub(crate) fn verify_denial(
    request: &[u8],
    response: &[u8],
) -> anyhow::Result<vos::agent::local_lifecycle::LocalCreateDenial> {
    match request.get(..4) {
        Some(b"LCQ1") => LocalCreateSubmission::decode(request)
            .and_then(|submission| submission.verify_denial(response))
            .map_err(|error| anyhow::anyhow!("invalid signed denial (LCQ1): {error:?}")),
        Some(b"LCQ2") => anyhow::bail!(
            "external-state Local Create is unsupported; preserve the retained request"
        ),
        _ => anyhow::bail!("unrecognized Local Create request format"),
    }
}

/// The caller must first authenticate the retained Create/Install submission;
/// a response cannot select its own trusted Authority or pending call.
pub(super) fn verify_call_acknowledgement(
    call: &AuthorityCredentialCall,
    response: &[u8],
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    use vos::agent::sdk::authority::{
        AuthorityVerifier, ManagementApplicationAck, ManagementApproval,
    };
    use vos::agent::sdk::wire::CanonicalWire as _;

    struct Verifier;
    impl AuthorityVerifier for Verifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            libp2p::identity::ed25519::PublicKey::try_from_bytes(public_key)
                .is_ok_and(|key| key.verify(message, signature))
        }
    }

    anyhow::ensure!(
        call.authenticated_node.is_none(),
        "retained request is not HTTP-compatible"
    );
    let ack = ManagementApplicationAck::decode(response)
        .map_err(|error| anyhow::anyhow!("invalid lifecycle acknowledgement: {error:?}"))?;
    anyhow::ensure!(
        ack.authority == call.authority,
        "acknowledgement Authority differs from retained request"
    );
    ack.verify_with(&Verifier)
        .map_err(|error| anyhow::anyhow!("invalid acknowledgement signature: {error:?}"))?;
    let selector = &ack.receipt.selector;
    let approval = ManagementApproval::from_call(
        call,
        ack.authorization_sequence,
        selector.evidence.clone(),
        selector.lane_roots,
        selector.epoch,
        selector.valid_from,
        selector.expires_at,
    )
    .map_err(|error| {
        anyhow::anyhow!("acknowledgement approval differs from retained request: {error:?}")
    })?;
    anyhow::ensure!(
        ack.matches_pending(call, &approval),
        "acknowledgement does not match the exact retained lifecycle request"
    );
    Ok(ack)
}

pub(crate) fn prepare(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: AgentDescriptor,
    runtime: AdmittedRuntimePackage,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalCreateSubmission> {
    let call = sign_create_call(
        operator,
        authority,
        &descriptor,
        sequence,
        valid_from,
        expires_at,
    )?;
    LocalCreateSubmission::new(descriptor, call, runtime)
        .map_err(|error| anyhow::anyhow!("invalid signed Local Create: {error:?}"))
}

fn sign_create_call(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: &AgentDescriptor,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<AuthorityCredentialCall> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.identity.owner == identity.principal(),
        "operator Local Create requires the operator as owner"
    );
    let managed = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let mut call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority,
        managed,
        principal: identity.principal(),
        credential: identity.credential(),
        request_sequence: sequence,
        credential_public_key: identity.raw_public_key(),
        authenticated_node: None,
        requested_valid_from: valid_from,
        requested_expires_at: expires_at,
        plan: request
            .authorization_plan()
            .ok_or_else(|| anyhow::anyhow!("invalid Local Create authorization plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())
        .map_err(|_| anyhow::anyhow!("Local Create signing failed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Local Create signature must be Ed25519"))?;
    Ok(call)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
    use vos::agent::sdk::{
        ActorId, AgentId, AgentIdentity, AgentProfile, AgentReplica, DeploymentId, Hash, NodeId,
        ProducerId, ProgramId, ReplicaRole, SpaceId,
    };

    #[test]
    fn retired_external_create_is_not_accepted_by_client_decoders() {
        let bytes = b"LCQ2retained-external-request";
        let error = decode_retained_request(bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("external-state Local Create is unsupported")
        );
        assert!(verify_denial(bytes, b"").is_err());
    }

    pub(crate) fn fixture() -> (
        Keypair,
        AuthorityActorTarget,
        AgentDescriptor,
        AdmittedRuntimePackage,
    ) {
        let operator = Keypair::ed25519_from_bytes([0x63; 32]).unwrap();
        let signer = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let runtime = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
        let space = SpaceId([1; 32]);
        let nonce = Hash([2; 32]);
        let binding = AgentAuthorityBinding {
            policy: Hash([3; 32]),
            issuer: AuthorityIssuer {
                principal: signer.principal(),
                actor: ActorId([4; 32]),
                deployment: DeploymentId([5; 32]),
                program: ProgramId([6; 32]),
                producer: ProducerId::of_public_key(&signer.raw_public_key()),
            },
            public_key: signer.raw_public_key(),
            initial_epoch: 1,
        };
        let authority = AuthorityActorTarget {
            space,
            system_agent: AgentId([7; 32]),
            system_runtime_deployment: runtime.deployment(),
            binding,
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, signer.principal(), nonce.as_bytes()),
                owner: signer.principal(),
                profile: AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: ProducerId([8; 32]),
            },
            creation_nonce: nonce,
            authority: binding,
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node: NodeId([9; 32]),
                principal: signer.principal(),
                role: ReplicaRole::Voter,
            }],
        };
        (operator, authority, descriptor, runtime)
    }

    #[test]
    fn exact_inputs_produce_identical_http_compatible_signed_submissions() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let first = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        let repeated = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        assert_eq!(first, repeated);
        assert!(first.len() <= LocalCreateSubmission::MAX_BYTES);
        let (_, call, _) = LocalCreateSubmission::decode(&first).unwrap().into_parts();
        assert_eq!(call.authenticated_node, None);
        assert_eq!(call.request_sequence, sequence);
        assert_eq!(
            (call.requested_valid_from, call.requested_expires_at),
            (10, 30)
        );
        let changed = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(3).unwrap(),
            10,
            30,
        )
        .unwrap();
        assert_ne!(changed.into_parts().1.invocation, call.invocation);
    }

    /// A host-signed certificate fixture, not a claim of Authority execution.
    /// Native vos tests separately prove the runtime/retirement preconditions.
    pub(crate) fn denial_fixture() -> (Vec<u8>, Vec<u8>) {
        use vos::actors::codec::Encode as _;
        use vos::agent::sdk::wire::CanonicalWire as _;
        use vos::agent::sdk::*;
        let (operator, authority, descriptor, runtime) = fixture();
        let submission = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(2).unwrap(),
            10,
            100,
        )
        .unwrap();
        let request = submission.encode();
        let (descriptor, call, _) = submission.into_parts();
        let mut message = vec![vos::actors::value::TAG_DYNAMIC];
        message.extend(
            vos::actors::value::Msg::new("authorize")
                .with(
                    "call",
                    vos::actors::value::Value::Bytes(call.encode().unwrap()),
                )
                .encode(),
        );
        let invocation = InvocationWork {
            space: authority.space,
            agent: authority.system_agent,
            runtime_deployment: authority.system_runtime_deployment,
            invocation: call.invocation,
            actor: authority.binding.issuer.actor,
            incarnation: Hash([19; 32]),
            deployment: authority.binding.issuer.deployment,
            program: authority.binding.issuer.program,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.principal),
                transport_node: None,
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            message,
            installation_data: None,
            availability: vec![],
            gas: 1,
            recovery_only: false,
        };
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 10));
        let work = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 10,
        };
        fn wire(magic: &[u8]) -> Vec<u8> {
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&vos::service::PLATFORM_ID.0);
            bytes
        }
        fn field(output: &mut Vec<u8>, bytes: &[u8]) {
            output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            output.extend_from_slice(bytes);
        }
        let mut intent = wire(b"CMI4");
        field(
            &mut intent,
            &ManagementRequest::Create(Box::new(descriptor))
                .encode()
                .unwrap(),
        );
        field(&mut intent, &call.encode().unwrap());
        intent.push(1);
        field(&mut intent, &work.encode().unwrap());
        intent.push(0);
        let mut anchor = wire(b"MJA1");
        anchor.extend_from_slice(&[21; 96]);
        anchor.extend_from_slice(&0u64.to_le_bytes());
        anchor.push(0);
        intent.push(1);
        field(&mut intent, &anchor);
        intent.push(0);
        let mut message = b"vos/agent/management-denial-retired/v1".to_vec();
        message.extend_from_slice(
            Hash::digest(b"vos/agent/management-denial-intent/v1", &[&intent]).as_bytes(),
        );
        let signature = operator.sign(&message).unwrap();
        intent[..4].copy_from_slice(b"CND1");
        intent.extend_from_slice(&signature);
        LocalCreateSubmission::decode(&request)
            .unwrap()
            .verify_denial(&intent)
            .unwrap();
        (request, intent)
    }

    #[test]
    fn signed_denial_http_response_requires_exact_certificate() {
        let (request, denial) = denial_fixture();
        let response = |body: &[u8]| {
            let mut bytes = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
            bytes.extend_from_slice(body);
            bytes
        };
        assert!(
            submit_fixture(&request, &response(&denial))
                .unwrap_err()
                .to_string()
                .contains("verified Local Create denial")
        );
        let mut corrupt = denial;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            submit_fixture(&request, &response(&corrupt))
                .unwrap_err()
                .to_string()
                .contains("invalid signed denial")
        );
        super::super::clean_store::tests::check_denial_retention(&request, &denial_fixture().1);
    }

    /// Opt-in real-daemon campaign. Use isolated XDG directories and a newly
    /// started space named native-denial-smoke. Retain all files on failure.
    #[test]
    #[ignore = "requires a freshly started disposable native-denial-smoke daemon"]
    fn real_daemon_denial_resume_then_valid_create() {
        use super::super::clean_store::{
            CleanCredentialReservation, CleanLocalCreateRequestFile, CredentialReservationStatus,
            ensure_private_directory,
        };
        let index = crate::spaces_index::load().unwrap();
        let entry = crate::spaces_index::find(&index, "native-denial-smoke").unwrap();
        let data = std::path::Path::new(&entry.data_dir);
        assert!(
            !data.join("agent-client").exists(),
            "fresh disposable client state required"
        );
        let space = SpaceId(hex::decode(&entry.id).unwrap().try_into().unwrap());
        let endpoint = super::super::endpoint::read(data).unwrap().unwrap();
        assert!(super::super::endpoint::is_alive(&endpoint));
        let peer: libp2p::PeerId = endpoint.peer_id.parse().unwrap();
        let public = vos::registry::ed25519_pubkey_from_peer_id(&peer.to_bytes()).unwrap();
        let config = super::super::local_config::load(data).unwrap();
        assert_eq!(config.ingress.http.len(), 1);
        let address = config.ingress.http[0].listen.parse().unwrap();
        let operator = crate::identity::load_existing().unwrap();
        let identity = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let nonce = Hash([0xd3; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provisional = prepare_fresh(
            &operator,
            space,
            public,
            nonce,
            NonZeroU64::new(2).unwrap(),
            now.saturating_sub(60),
            now + 3600,
        )
        .unwrap();
        let (_, provisional_call, _) = provisional.into_parts();
        let root = data.join("agent-client");
        ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        ensure_private_directory(&claims).unwrap();
        let operations = root.join("operations");
        ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(identity.credential().0),
            hex::encode(nonce.0)
        ));
        ensure_private_directory(&operation).unwrap();
        {
            let mut reservation =
                CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                    .unwrap();
            reservation.reserve(nonce).unwrap();
            // Production bootstrap itself consumes a credential sequence.
            // Discover rather than copying the isolated Authority fixture's
            // initial sequence assumption into a real daemon campaign.
            let (_, sequence) = discover_credential(
                &operation.join("query"),
                address,
                &operator,
                provisional_call.authority,
            )
            .unwrap();
            let wrong_sequence = NonZeroU64::new(sequence.get().checked_add(1).unwrap()).unwrap();
            let request = prepare_fresh(
                &operator,
                space,
                public,
                nonce,
                wrong_sequence,
                now.saturating_sub(60),
                now + 3600,
            )
            .unwrap()
            .encode();
            CleanLocalCreateRequestFile::open_or_create(operation.join("request"))
                .unwrap()
                .publish(&request)
                .unwrap();
        }
        let mut denied = false;
        for attempt in 0..3 {
            let error = create_local(data, address, &operator, space, public, true).unwrap_err();
            println!("denial attempt {attempt}: {error}");
            if error.to_string().contains("signed denial retained") {
                denied = true;
                break;
            }
        }
        assert!(denied, "denial did not reach durable client completion");
        assert!(
            create_local(data, address, &operator, space, public, true)
                .unwrap_err()
                .to_string()
                .contains("signed denial retained")
        );
        assert_eq!(
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap()
                .current()
                .unwrap(),
            Some((nonce, CredentialReservationStatus::Denied))
        );
        let mut result = create_local(data, address, &operator, space, public, false);
        for attempt in 0..3 {
            if result.is_ok() {
                break;
            }
            println!(
                "valid Create retry {attempt}: {}",
                result.as_ref().unwrap_err()
            );
            result = create_local(data, address, &operator, space, public, true);
        }
        let acknowledgement = result.unwrap();
        assert_eq!(
            create_local(data, address, &operator, space, public, true).unwrap(),
            acknowledgement
        );
        println!("real daemon denial, local resume, valid successor and exact ACK retry passed");
    }

    #[test]
    fn fresh_preparation_uses_startup_authority_and_only_the_node_public_key() {
        let operator = Keypair::ed25519_from_bytes([0x63; 32]).unwrap();
        let node = Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        let public = node.public().try_into_ed25519().unwrap().to_bytes();
        let space = SpaceId([1; 32]);
        let sequence = NonZeroU64::new(2).unwrap();
        let first =
            prepare_fresh(&operator, space, public, Hash([2; 32]), sequence, 10, 30).unwrap();
        let encoded = first.encode();
        assert_eq!(
            prepare_fresh(&operator, space, public, Hash([2; 32]), sequence, 10, 30)
                .unwrap()
                .encode(),
            encoded
        );
        let (descriptor, call, runtime) = first.into_parts();
        let authority_package = crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            "system-authority",
            &operator,
        )
        .unwrap();
        let root_public = CleanOperatorIdentitySigner::new(&operator)
            .unwrap()
            .raw_public_key();
        let (expected, nonce) = super::super::clean_startup::derive_system_authority_target(
            space,
            root_public,
            &runtime,
            &authority_package,
        )
        .unwrap();
        assert_eq!(call.authority, expected);
        assert_eq!(
            nonce,
            Hash::digest(
                b"vos/system-agent/creation-nonce/v1",
                &[space.as_bytes(), &root_public]
            )
        );
        assert_eq!(
            expected.system_agent,
            AgentId::derive(space, descriptor.identity.owner, nonce.as_bytes())
        );
        assert_eq!(
            expected.binding.policy,
            Hash::digest(
                b"vos/system-authority/policy-binding/v1",
                &[
                    space.as_bytes(),
                    expected.system_agent.as_bytes(),
                    authority_package.package_ref().hash.as_bytes(),
                ]
            )
        );
        assert_eq!(
            descriptor.replicas[0].node,
            super::super::clean_identity::node_id_from_authenticated_peer(
                &node.public().to_peer_id()
            )
        );
        assert_eq!(descriptor.replicas[0].principal, descriptor.identity.owner);
        assert_eq!(
            descriptor.identity.transition_producer,
            ProducerId::of_public_key(&public)
        );
        assert!(
            prepare_fresh(
                &operator,
                space,
                root_public,
                Hash([2; 32]),
                sequence,
                10,
                30
            )
            .is_err()
        );
        assert!(
            super::super::clean_startup::derive_system_authority_target(
                space,
                public,
                &runtime,
                &authority_package
            )
            .is_err()
        );
        assert!(
            prepare_fresh(
                &operator,
                SpaceId::ZERO,
                public,
                Hash([2; 32]),
                sequence,
                10,
                30
            )
            .is_err()
        );
    }

    #[test]
    fn credential_discovery_binds_query_owner_status_and_management_sequence() {
        use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
        use vos::agent::sdk::authority::{
            AuthorityBuiltinRole, AuthorityCredentialKind, AuthorityCredentialProjection,
            AuthorityCredentialStatus, AuthorityProjectionHead, AuthorityProjectionSelector,
        };
        use vos::agent::sdk::{PrincipalId, wire::CanonicalWire as _};
        let (operator, authority, descriptor, _) = fixture();
        let owner = descriptor.identity.owner;
        let mut signer = super::super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(operator).unwrap();
        let query = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        let one = NonZeroU64::new(1).unwrap();
        let projection = AuthorityCredentialProjection {
            query: query.clone(),
            head: AuthorityProjectionHead {
                state_revision: one,
                epoch: one,
                authorization_sequence: one,
                administration_generation: one,
                state_commitment: Hash([21; 32]),
            },
            principal: owner,
            status: AuthorityCredentialStatus::Active,
            kind: AuthorityCredentialKind::Api,
            builtin_role: AuthorityBuiltinRole::Admin,
            management_request_high_water: 1,
            operation_request_high_water: 99,
            admin_request_high_water: 999,
            space_roles: vec![],
            actor_roles: vec![],
            capabilities: vec![],
        };
        let bytes = projection.encode().unwrap();
        let (decoded, next) = validate_credential_response(&query, owner, &bytes).unwrap();
        assert_eq!(decoded, projection);
        assert_eq!(next.get(), 2);
        let (_, operation_next) = validate_credential_response_for(
            &query,
            owner,
            &bytes,
            CredentialSequenceDomain::Operation,
        )
        .unwrap();
        assert_eq!(operation_next.get(), 100);
        let (_, admin_next) = validate_credential_response_for(
            &query,
            owner,
            &bytes,
            CredentialSequenceDomain::Admin,
        )
        .unwrap();
        assert_eq!(admin_next.get(), 1000);
        let mut other_domains_exhausted = projection.clone();
        other_domains_exhausted.management_request_high_water = u64::MAX;
        other_domains_exhausted.operation_request_high_water = u64::MAX;
        assert_eq!(
            validate_credential_response_for(
                &query,
                owner,
                &other_domains_exhausted.encode().unwrap(),
                CredentialSequenceDomain::Admin
            )
            .unwrap()
            .1
            .get(),
            1000
        );
        other_domains_exhausted.admin_request_high_water = u64::MAX;
        assert!(
            validate_credential_response_for(
                &query,
                owner,
                &other_domains_exhausted.encode().unwrap(),
                CredentialSequenceDomain::Admin
            )
            .is_err()
        );
        let mut management_exhausted = projection.clone();
        management_exhausted.management_request_high_water = u64::MAX;
        assert_eq!(
            validate_credential_response_for(
                &query,
                owner,
                &management_exhausted.encode().unwrap(),
                CredentialSequenceDomain::Operation
            )
            .unwrap()
            .1
            .get(),
            100
        );
        let mut operation_exhausted = projection.clone();
        operation_exhausted.operation_request_high_water = u64::MAX;
        assert!(
            validate_credential_response_for(
                &query,
                owner,
                &operation_exhausted.encode().unwrap(),
                CredentialSequenceDomain::Operation
            )
            .is_err()
        );
        assert_eq!(
            validate_credential_response(&query, owner, &operation_exhausted.encode().unwrap())
                .unwrap()
                .1
                .get(),
            2
        );
        assert!(validate_credential_response(&query, PrincipalId([22; 32]), &bytes).is_err());
        assert!(validate_credential_response(&query, owner, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(validate_credential_response(&query, owner, &trailing).is_err());
        for variant in 0..4 {
            let mut changed = projection.clone();
            match variant {
                0 => changed.status = AuthorityCredentialStatus::Revoked,
                1 => changed.kind = AuthorityCredentialKind::Ssh,
                2 => changed.query.nonce = Hash([23; 32]),
                _ => changed.management_request_high_water = u64::MAX,
            }
            assert!(
                validate_credential_response(&query, owner, &changed.encode().unwrap()).is_err()
            );
        }
        let mut forged = query.clone();
        let vos::agent::sdk::authority::AuthorityIngressAuthentication::ApiCredentialSignature {
            signature,
            ..
        } = &mut forged.authentication
        else {
            unreachable!()
        };
        signature[0] ^= 1;
        assert!(
            query_credential(
                "127.0.0.1:1".parse().unwrap(),
                &forged.encode().unwrap(),
                owner
            )
            .unwrap_err()
            .to_string()
            .contains("signature")
        );
    }

    #[test]
    fn acknowledgement_requires_both_signatures_and_exact_request_and_reply() {
        use vos::agent::sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
            ManagementApplicationAck, ManagementApproval,
        };
        use vos::agent::sdk::{ManagementReply, wire::CanonicalWire as _};
        let (operator, authority, descriptor, runtime) = fixture();
        let request = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode();
        let (_, call, _) = LocalCreateSubmission::decode(&request)
            .unwrap()
            .into_parts();
        let approval = ManagementApproval::from_call(
            &call,
            NonZeroU64::new(3).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([10; 32]),
            },
            AuthorityLaneRoots::default(),
            1,
            10,
            30,
        )
        .unwrap();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: authority.binding.policy,
                issuer: authority.binding.issuer,
                space: call.managed.space,
                agent: call.managed.agent,
                operation: call.plan.authority_operation(),
                runtime_deployment: call.managed.runtime_deployment,
                actor: None,
                actor_deployment: None,
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: 1,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 30,
                request: approval.plan_commitment,
            },
            public_key: authority.binding.public_key,
            signature: [0; 64],
        };
        receipt.signature = operator
            .sign(&receipt.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            receipt,
            application: ManagementReply::Created(descriptor.identity.clone()),
            reopened_state: Hash([11; 32]),
            applied_at: 20,
            signature: [0; 64],
        };
        let sign = |ack: &mut ManagementApplicationAck| {
            ack.signature = operator
                .sign(&ack.signing_bytes())
                .unwrap()
                .try_into()
                .unwrap();
        };
        sign(&mut ack);
        let bytes = ack.encode().unwrap();
        super::super::clean_store::tests::check_reservation_completion(&request, &bytes);
        super::super::clean_store::tests::check_acknowledgement_storage(&request, &bytes);
        assert_eq!(verify_acknowledgement(&request, &bytes).unwrap(), ack);
        let mut http = format!("HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
        http.extend_from_slice(&bytes);
        assert_eq!(submit_fixture(&request, &http).unwrap(), ack);
        let conflict = submit_fixture(
            &request,
            b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap_err()
        .to_string();
        assert!(conflict.contains("request retained"));
        assert!(conflict.contains("inspect operation evidence"));
        assert!(conflict.contains("does not prove the original operation failed"));
        assert!(!conflict.contains("retry these exact bytes"));
        for response in [
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMAA2".as_slice(),
        ] {
            assert!(submit_fixture(&request, response).unwrap_err().to_string().contains("request retained"));
        }
        let size = vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES + 1;
        let mut oversized = format!("HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n").into_bytes();
        oversized.resize(oversized.len() + size, 0);
        assert!(
            submit_fixture(&request, &oversized)
                .unwrap_err()
                .to_string()
                .contains("wire limit")
        );
        assert!(verify_acknowledgement(&request, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(verify_acknowledgement(&request, &trailing).is_err());
        let other_request = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(3).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode();
        assert!(verify_acknowledgement(&other_request, &bytes).is_err());
        let mut forged = ack.clone();
        forged.signature[0] ^= 1;
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.receipt.signature[0] ^= 1;
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.approval = Hash([12; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.authority.system_agent = AgentId([14; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack;
        let ManagementReply::Created(identity) = &mut forged.application else {
            unreachable!()
        };
        identity.runtime_program = ProgramId([13; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
    }

    fn submit_fixture(
        request: &[u8],
        response: &[u8],
    ) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalCreateRequestFile};
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::DirBuilderExt as _;
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = Directory(
            std::env::temp_dir().join(format!("vosx-local-submit-{}", hex::encode(nonce))),
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir.0)
            .unwrap();
        let root = dir.0.join("request");
        CleanLocalCreateRequestFile::open_or_create(&root)
            .unwrap()
            .publish(request)
            .unwrap();
        let expected = request.to_vec();
        let response = response.to_vec();
        let leased_root = root.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "client never connected"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 8192);
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            assert!(header.starts_with(b"POST /__agents/local HTTP/1.1\r\n"));
            let mut body = vec![0; expected.len()];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, expected);
            assert!(matches!(
                CleanLocalCreateRequestFile::open_or_create(leased_root),
                Err(CleanFileStoreError::Busy)
            ));
            let _ = stream.write_all(&response);
        });
        let result = submit_retained(&root, address);
        server.join().unwrap();
        assert_eq!(
            CleanLocalCreateRequestFile::open_or_create(&root)
                .unwrap()
                .load()
                .unwrap()
                .unwrap(),
            request
        );
        result
    }

    #[test]
    fn preparation_rejects_wrong_owner_scope_window_and_runtime() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let other = Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        assert!(
            prepare(
                &other,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        assert!(
            prepare(
                &operator,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                30,
                10
            )
            .is_err()
        );
        let mut wrong_scope = authority;
        wrong_scope.space = SpaceId([99; 32]);
        assert!(
            prepare(
                &operator,
                wrong_scope,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        let wrong_runtime = crate::bundled::root_signed_agent_runtime_package(&other).unwrap();
        assert!(
            prepare(
                &operator,
                authority,
                descriptor,
                wrong_runtime,
                sequence,
                10,
                30
            )
            .is_err()
        );
    }
}
