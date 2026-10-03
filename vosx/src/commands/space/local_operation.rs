//! Credential-reserved Local invocation authorization. Physical application is
//! a separate gate; an issued receipt does not complete this reservation.
#[cfg(test)]
#[path = "local_operation_live_tests.rs"]
mod live_tests;
#[cfg(test)]
#[path = "local_yield_live_tests.rs"]
mod yield_live_tests;
use super::clean_store::{
    CleanCredentialReservation, CleanOperationClientFile, CleanPreparationClientFile,
    CredentialReservationStatus, ensure_private_directory,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::authority_operation::AuthorityOperationIntent;
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{AgentProfile, Hash, ProducerId, SpaceId};
use vos::agent::supervisor_adapters::AgentTargetedPreparationRequest;

#[derive(clap::Args, Debug)]
pub struct AuthorizeLocalArgs {
    pub space: String,
    /// Canonical ATQ1 with an explicit stable invocation ID and operator origin.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pub intent: Option<PathBuf>,
    /// Resume the current credential reservation without reading new intent.
    #[arg(long)]
    pub resume: bool,
    #[arg(long)]
    pub http: Option<SocketAddr>,
}

pub(crate) fn run(args: AuthorizeLocalArgs) -> anyhow::Result<()> {
    run_with_application(args, false)
}

pub(crate) fn run_invocation(args: AuthorizeLocalArgs) -> anyhow::Result<()> {
    run_with_application(args, true)
}

fn run_with_application(args: AuthorizeLocalArgs, apply: bool) -> anyhow::Result<()> {
    use std::io::Read as _;
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let operator = crate::identity::load_existing()?;
    let initial = args
        .intent
        .as_ref()
        .map(|path| -> anyhow::Result<_> {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(AgentTargetedPreparationRequest::MAX_ENCODED_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            AgentTargetedPreparationRequest::decode(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid ATQ1: {e:?}"))
        })
        .transpose()?;
    let (root, response) = authorize_with_application(
        &data,
        address,
        &operator,
        space,
        node_public,
        initial.as_ref(),
        apply,
    )?;
    let denied = response[4] == 1; // Verified canonical AOR1.
    let mut output = serde_json::json!({
        "decision": if denied { "denied" } else { "issued" },
        "request_dir": root, "response": hex::encode(response),
        "decision_retained": true, "applied": false, "reservation_pending": !denied,
    });
    if apply && !denied {
        output.as_object_mut().expect("object").remove("applied");
        output["delivery_retired"] = true.into();
        output["reservation_pending"] = false.into();
    }
    crate::output::print_json(&output);
    Ok(())
}

pub(super) fn authorize(
    data: &Path,
    address: SocketAddr,
    operator: &libp2p::identity::Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    initial: Option<&AgentTargetedPreparationRequest>,
) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    authorize_with_application(data, address, operator, space, node_public, initial, false)
}

pub(super) fn authorize_with_application(
    data: &Path,
    address: SocketAddr,
    operator: &libp2p::identity::Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    initial: Option<&AgentTargetedPreparationRequest>,
    apply: bool,
) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    authorize_with_application_validity(
        data,
        address,
        operator,
        space,
        node_public,
        initial,
        apply,
        3600,
    )
}

// The CLI always uses its original one-hour validity. The explicit internal
// parameter lets the disposable live test sign a genuinely short-lived call,
// without backdating requests or changing any server clock/timeout.
fn authorize_with_application_validity(
    data: &Path,
    address: SocketAddr,
    operator: &libp2p::identity::Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    initial: Option<&AgentTargetedPreparationRequest>,
    apply: bool,
    validity_secs: u64,
) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    anyhow::ensure!(validity_secs > 0, "authorization validity must be positive");
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "Local authorization requires nonzero loopback HTTP"
    );
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_data_dir(data)?,
        "system-authority",
        operator,
    )?;
    let (authority, _) = super::clean_startup::derive_system_authority_target(
        space,
        identity.raw_public_key(),
        &runtime,
        &package,
    )?;
    if let Some(request) = initial {
        validate_intent(request, space, &identity)?;
    }
    let root = data.join("agent-client");
    let _root = ensure_private_directory(&root)?;
    let claims = root.join("credentials");
    let _claims = ensure_private_directory(&claims)?;
    let mut reservation =
        CleanCredentialReservation::open_or_create(&claims, space, identity.credential())?;
    let nonce = match initial {
        Some(request) => Hash(request.intent().invocation().0),
        None => {
            reservation
                .current()?
                .ok_or_else(|| anyhow::anyhow!("no invocation authorization to resume"))?
                .0
        }
    };
    let operations = root.join("operations");
    let _operations = ensure_private_directory(&operations)?;
    let operation = operations.join(format!(
        "{}-{}",
        hex::encode(identity.credential().0),
        hex::encode(nonce.0)
    ));
    if initial.is_some()
        && let Some((current, CredentialReservationStatus::Pending)) = reservation.current()?
    {
        anyhow::ensure!(
            current == nonce,
            "another credential operation is pending; resume its original command"
        );
    }
    let _operation = ensure_private_directory(&operation)?;
    if let Some(intent) = initial {
        // A human-readable call generates its nonce in this process. Publish
        // the exact ATQ1 before reserving the credential so a crash after
        // reservation can always resume it without reconstructing arguments
        // or minting a replacement invocation ID. A pre-reservation orphan is
        // inert and never becomes a signed operation.
        let mut retained =
            CleanPreparationClientFile::open_or_create(operation.join("preparation"))?;
        let bytes = intent
            .encode()
            .map_err(|e| anyhow::anyhow!("invalid ATQ1: {e:?}"))?;
        match retained.load_request()? {
            Some(existing) => {
                anyhow::ensure!(existing == bytes, "retained intent differs from input")
            }
            None => retained.publish_request(&bytes)?,
        }
    }
    let status = reservation.reserve(nonce)?;
    // The common request namespace rejects a pending Create/Install record
    // instead of reinterpreting it as an invocation authorization.
    let request_root = operation.join("request");
    let mut delivery = CleanOperationClientFile::open_or_create(&request_root)?;
    let request = match delivery.load_request()? {
        Some(bytes) => bytes, // No discovery, physical preparation or signing on retry.
        None => {
            delivery.load_response()?; // Reject orphan/corrupt delivery before discovery.
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "terminal reservation is missing its authorization request"
            );
            let preparation_root = operation.join("preparation");
            let mut retained = CleanPreparationClientFile::open_or_create(&preparation_root)?;
            let intent = match retained.load_request()? {
                Some(bytes) => AgentTargetedPreparationRequest::decode(&bytes)
                    .map_err(|e| anyhow::anyhow!("invalid retained ATQ1: {e:?}"))?,
                None => {
                    let request = initial.ok_or_else(|| {
                        anyhow::anyhow!("no retained intent; retry the original --intent input")
                    })?;
                    retained.publish_request(
                        &request
                            .encode()
                            .map_err(|e| anyhow::anyhow!("invalid ATQ1: {e:?}"))?,
                    )?;
                    request.clone()
                }
            };
            validate_intent(&intent, space, &identity)?;
            anyhow::ensure!(
                intent.intent().invocation().0 == nonce.0,
                "retained intent differs from reservation"
            );
            drop(retained);
            let mut host_preparation = CleanOperationClientFile::open_authorization_preparation(
                operation.join("authorization-preparation"),
            )?;
            host_preparation.load_response()?; // Reject orphan/corrupt preparation before discovery.
            if host_preparation.load_request()?.is_none() {
                let (credential, _) = super::local_create::discover_operation_credential(
                    &operation.join("query"),
                    address,
                    operator,
                    authority,
                )?;
                let descriptor = super::local_install::discover_agent(
                    address,
                    operator,
                    authority,
                    credential.head,
                    intent.target().agent(),
                )?;
                // Ordinary Shared Agents replicated on this node use the same
                // credential-reserved invocation path as Local Agents.
                let local_node = super::clean_identity::node_id_from_authenticated_peer(
                    &libp2p::identity::PublicKey::from(
                        libp2p::identity::ed25519::PublicKey::try_from_bytes(&node_public)
                            .map_err(|_| anyhow::anyhow!("invalid node public key"))?,
                    )
                    .to_peer_id(),
                );
                anyhow::ensure!(
                    (descriptor.identity.profile == AgentProfile::Local
                        || (descriptor.identity.profile == AgentProfile::Shared
                            && descriptor
                                .replicas
                                .iter()
                                .any(|replica| replica.node == local_node)))
                        && descriptor.identity.owner == identity.principal()
                        && descriptor.identity.transition_producer
                            == ProducerId::of_public_key(&node_public),
                    "target is not an operator-owned Local Agent of this node"
                );
                let key = operator.clone().try_into_ed25519()?;
                let secret = key.secret();
                let token = vos::ingress::encode_access_token(secret.as_ref().try_into()?)
                    .ok_or_else(|| anyhow::anyhow!("invalid access token"))?;
                let prepared = super::local_invocation::prepare_retained(
                    &preparation_root,
                    address,
                    &token,
                    None,
                )?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let timing = super::operation_authorization::preparation::Timing {
                    authorization_slot: now,
                    issued_at: now,
                    valid_from: now.saturating_sub(60),
                    expires_at: now
                        .checked_add(validity_secs)
                        .ok_or_else(|| anyhow::anyhow!("validity overflow"))?,
                };
                let submission = super::operation_authorization::preparation::prepare(
                    operator,
                    authority,
                    &descriptor,
                    &credential,
                    &prepared,
                    timing,
                )?;
                // Only the signed call survives this client-side construction.
                // The final context must come from durable native clock capture.
                host_preparation.publish_request(
                    &submission
                        .call()
                        .encode()
                        .map_err(|e| anyhow::anyhow!("invalid AOC5: {e:?}"))?,
                )?;
            }
            let mut retained = CleanPreparationClientFile::open_or_create(&preparation_root)?;
            let response = retained
                .load_response()?
                .ok_or_else(|| anyhow::anyhow!("signed call is missing actor preparation"))?;
            let response =
                vos::agent::supervisor_adapters::AgentTargetedPreparationResponse::decode(
                    &response,
                )
                .map_err(|e| anyhow::anyhow!("invalid retained ATP1: {e:?}"))?;
            let prepared = response
                .for_request(&intent)
                .ok_or_else(|| anyhow::anyhow!("actor preparation differs from retained intent"))?;
            let call = vos::agent::sdk::authority_operation::AuthorityOperationCall::decode(
                &host_preparation
                    .load_request()?
                    .ok_or_else(|| anyhow::anyhow!("missing retained AOC5"))?,
            )
            .map_err(|e| anyhow::anyhow!("invalid retained AOC5: {e:?}"))?;
            anyhow::ensure!(
                call.authority == authority
                    && call.principal == identity.principal()
                    && call.credential == identity.credential()
                    && matches!(
                        call.intent.managed().profile,
                        AgentProfile::Local | AgentProfile::Shared
                    )
                    && call.intent.managed().owner == identity.principal()
                    && call.intent.managed().transition_producer
                        == ProducerId::of_public_key(&node_public)
                    && call.intent.matches_invocation_work(prepared.work()),
                "retained call differs from operator, node or actor preparation"
            );
            let bytes = super::operation_authorization::prepare_retained(
                &mut host_preparation,
                address,
                prepared.observed_slot(),
            )?;
            delivery.publish_request(&bytes)?;
            bytes
        }
    };
    let submission = AuthorityOperationSubmission::decode(&request)
        .map_err(|e| anyhow::anyhow!("invalid retained AOQ1: {e:?}"))?;
    let call = submission.call();
    let AuthorityOperationIntent::InvokeActor {
        managed,
        operation_invocation,
        ..
    } = &call.intent
    else {
        anyhow::bail!("retained request is not invocation authorization");
    };
    anyhow::ensure!(
        call.authority == authority
            && call.principal == identity.principal()
            && call.credential == identity.credential()
            && call.authenticated_node().is_none()
            && managed.space == space
            && matches!(managed.profile, AgentProfile::Local | AgentProfile::Shared)
            && managed.owner == identity.principal()
            && managed.transition_producer == ProducerId::of_public_key(&node_public)
            && operation_invocation.0 == nonce.0,
        "retained authorization differs from Space, operator, node or reservation"
    );
    drop(delivery);
    let response = super::operation_authorization::submit(&request_root, None, address)?;
    match submission
        .decode_response(&response)
        .map_err(|e| anyhow::anyhow!("invalid AOR1: {e:?}"))?
    {
        vos::agent::clean_bootstrap::NativeAuthorityOperationDecision::Denied { .. } => {
            let mut delivery = CleanOperationClientFile::open_or_create(&request_root)?;
            reservation.deny_operation(&mut delivery)?;
        }
        vos::agent::clean_bootstrap::NativeAuthorityOperationDecision::Issued(_) => {
            let application_root = operation.join("application");
            super::operation_authorization::application::retain(
                &request_root,
                &operation.join("preparation"),
                &application_root,
            )?;
            if apply {
                super::local_invocation::submit(&application_root, None, address)?;
                super::invocation_progress::continue_retained(&application_root, address)?;
                let mut authorization = CleanOperationClientFile::open_or_create(&request_root)?;
                let mut application =
                    super::clean_store::CleanInvocationFile::open_or_create(&application_root)?;
                reservation.complete_operation(&mut authorization, &mut application)?;
            }
        }
    }
    Ok((request_root, response))
}

fn validate_intent(
    request: &AgentTargetedPreparationRequest,
    space: SpaceId,
    identity: &super::clean_identity::CleanOperatorIdentitySigner<'_>,
) -> anyhow::Result<()> {
    let origin = request.intent().origin();
    anyhow::ensure!(
        request.target().space() == space
            && origin.principal == Some(identity.principal())
            && origin.credential == Some(identity.credential())
            && origin.transport_node.is_none()
            && origin.actor.is_none(),
        "intent must target this Space with the selected operator credential, without actor or transport impersonation"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Args {
        #[command(subcommand)]
        command: super::super::SpaceCommand,
    }
    #[test]
    fn managed_authorization_requires_exact_intent_or_explicit_resume() {
        for input in [
            vec![
                "vosx",
                "authorize-local-invocation",
                "test",
                "--intent",
                "intent.atq1",
            ],
            vec!["vosx", "authorize-local-invocation", "test", "--resume"],
        ] {
            for command in ["authorize-local-invocation", "invoke-local"] {
                let mut input = input.clone();
                input[1] = command;
                assert!(Args::try_parse_from(input).is_ok());
            }
        }
        for input in [
            vec!["vosx", "authorize-local-invocation", "test"],
            vec![
                "vosx",
                "authorize-local-invocation",
                "test",
                "--resume",
                "--intent",
                "other.atq1",
            ],
        ] {
            for command in ["authorize-local-invocation", "invoke-local"] {
                let mut input = input.clone();
                input[1] = command;
                assert!(Args::try_parse_from(input).is_err());
            }
        }
    }

    #[test]
    fn fresh_authorization_retains_intent_before_failed_discovery_and_reuses_it() {
        use std::os::unix::fs::DirBuilderExt as _;
        use vos::agent::sdk::{
            ActorId, InvocationId, InvocationOrigin, InvocationRoleClaims, MethodMode,
        };
        use vos::agent::supervisor::AgentRouteKey;
        use vos::agent::supervisor_adapters::AgentInvocationIntent;
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let identity =
            super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let data =
            std::env::temp_dir().join(format!("vosx-fresh-operation-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data)
            .unwrap();
        let make = |actor, origin| {
            AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(
                    authority.space,
                    descriptor.identity.agent,
                    ActorId([actor; 32]),
                )
                .unwrap(),
                AgentInvocationIntent::new(
                    InvocationId([0x51; 32]),
                    MethodMode::Linear,
                    origin,
                    InvocationRoleClaims::none(),
                    vec![1],
                    100,
                    false,
                )
                .unwrap(),
            )
            .unwrap()
        };
        let invalid = make(0x52, InvocationOrigin::anonymous());
        let address = "127.0.0.1:1".parse().unwrap();
        assert!(
            authorize(
                &data,
                address,
                &operator,
                authority.space,
                [0x53; 32],
                Some(&invalid)
            )
            .is_err()
        );
        assert!(!data.join("agent-client").exists());
        let origin = InvocationOrigin {
            principal: Some(identity.principal()),
            credential: Some(identity.credential()),
            ..InvocationOrigin::anonymous()
        };
        let initial = make(0x52, origin);
        assert!(
            authorize(
                &data,
                address,
                &operator,
                authority.space,
                [0x53; 32],
                Some(&initial)
            )
            .is_err()
        );
        let root = data.join("agent-client");
        let operation = root.join("operations").join(format!(
            "{}-{}",
            hex::encode(identity.credential().0),
            hex::encode(initial.intent().invocation().0)
        ));
        let saved_query = std::fs::read(operation.join("query/credential.query")).unwrap();
        for supplied in [None, Some(make(0x54, origin))] {
            assert!(
                authorize(
                    &data,
                    address,
                    &operator,
                    authority.space,
                    [0x53; 32],
                    supplied.as_ref()
                )
                .is_err()
            );
            let mut retained =
                CleanPreparationClientFile::open_or_create(operation.join("preparation")).unwrap();
            assert_eq!(
                retained.load_request().unwrap(),
                Some(initial.encode().unwrap())
            );
            assert!(retained.load_response().unwrap().is_none());
            assert_eq!(
                std::fs::read(operation.join("query/credential.query")).unwrap(),
                saved_query
            );
            let mut delivery =
                CleanOperationClientFile::open_or_create(operation.join("request")).unwrap();
            assert!(delivery.load_request().unwrap().is_none());
        }
        let mut reservation = CleanCredentialReservation::open_or_create(
            &root.join("credentials"),
            authority.space,
            identity.credential(),
        )
        .unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((
                Hash(initial.intent().invocation().0),
                CredentialReservationStatus::Pending
            ))
        );
        assert!(reservation.reserve(Hash([0x55; 32])).is_err());
        drop(reservation);
        std::fs::remove_dir_all(data).unwrap();
    }
}
