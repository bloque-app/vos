//! Exact retained Local Install delivery. No sequence allocation or signing
//! occurs during submission; an ambiguous response never changes the request.

use vos::agent::local_lifecycle::LocalInstallSubmission;
use vos::agent::sdk::authority::ManagementApplicationAck;
use vos::agent::sdk::wire::CanonicalWire as _;

#[derive(clap::Args, Debug)]
pub struct InstallLocalArgs {
    pub space: String,
    /// Full target Agent ID (hex), discovered again from the live Authority.
    pub agent: String,
    /// Signed VOS3 actor package; ignored once --resume finds a retained request.
    pub package: std::path::PathBuf,
    #[arg(long)]
    pub name: Option<String>,
    /// Exact encoded constructor bytes, if required by the package schema.
    #[arg(long)]
    pub constructor_data: Option<std::path::PathBuf>,
    #[arg(long)]
    pub http: Option<std::net::SocketAddr>,
    #[arg(long)]
    pub resume: bool,
    /// The Agent owner's ceiling for this actor's program, in bytes. Above
    /// the standard actor profile a package must also declare its resources;
    /// the runtime never executes more than its hard maximum.
    #[arg(long, default_value_t = vos::agent::sdk::STANDARD_ACTOR_PROGRAM_BYTES as u32)]
    pub max_program_bytes: u32,
}

/// The owner's admission ceilings for a new Install.
fn install_ceilings(
    args: &InstallLocalArgs,
) -> anyhow::Result<vos::agent::package_admission::ActorResourceCeilings> {
    let ceilings = vos::agent::package_admission::ActorResourceCeilings {
        max_program_bytes: args.max_program_bytes,
        ..vos::agent::package_admission::ActorResourceCeilings::standard()
    };
    anyhow::ensure!(
        ceilings.is_valid(),
        "--max-program-bytes must be between 1 and the runtime maximum of {} B",
        vos::agent::sdk::MAX_RUNTIME_PROGRAM_BYTES
    );
    Ok(ceilings)
}

pub(crate) fn run_install(args: InstallLocalArgs) -> anyhow::Result<()> {
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let agent = vos::agent::sdk::AgentId(
        hex::decode(&args.agent)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid full Agent ID"))?,
    );
    let operator = crate::identity::load_existing()?;
    let ack = install_local(&data, address, &operator, space, node_public, agent, &args)?;
    print_acknowledgement(&ack)
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "input exceeds the allowed size: {}",
        path.display()
    );
    Ok(bytes)
}

fn install_local(
    data: &std::path::Path,
    address: std::net::SocketAddr,
    operator: &libp2p::identity::Keypair,
    space: vos::agent::sdk::SpaceId,
    node_public: [u8; 32],
    agent: vos::agent::sdk::AgentId,
    args: &InstallLocalArgs,
) -> anyhow::Result<ManagementApplicationAck> {
    use super::clean_store::{
        CleanCredentialReservation, CleanLocalInstallFile, CredentialReservationStatus,
        ensure_private_directory,
    };
    use vos::agent::sdk::{AgentProfile, Hash, InstallationId, ProducerId};
    anyhow::ensure!(
        address.ip().is_loopback()
            && address.port() != 0
            && agent != vos::agent::sdk::AgentId::ZERO,
        "invalid Local Install target/endpoint"
    );
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
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
    let nonce = match reservation.current()? {
        Some((nonce, _)) if args.resume => nonce,
        Some((nonce, CredentialReservationStatus::Pending)) => anyhow::bail!(
            "credential operation {} is pending; resume its original command",
            hex::encode(nonce.0)
        ),
        _ if args.resume => anyhow::bail!("no Install operation to resume"),
        _ => {
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|error| anyhow::anyhow!("Install nonce entropy: {error}"))?;
            anyhow::ensure!(nonce != [0; 32], "zero Install nonce");
            Hash(nonce)
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
    let mut store = CleanLocalInstallFile::open_or_create(&request_root)?;
    let request = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "completed Install is missing its retained request"
            );
            // A new Install is where the owner's ceilings apply; the retained
            // request is later re-admitted on its bytes alone.
            let package = vos::agent::package_admission::admit_actor_package_within(
                &read_bounded(
                    &args.package,
                    vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES,
                )?,
                install_ceilings(args)?,
            )
            .map_err(|error| anyhow::anyhow!("invalid actor package: {error}"))?;
            let constructor = args
                .constructor_data
                .as_ref()
                .map(|path| read_bounded(path, vos::agent::sdk::MAX_INSTALLATION_DATA_BYTES))
                .transpose()?;
            let name = args
                .name
                .clone()
                .unwrap_or_else(|| package.manifest().name.clone());
            let registry_reservation = Hash::digest(
                b"vos/local-install/registry-reservation/v1",
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    nonce.as_bytes(),
                    package.package_ref().hash.as_bytes(),
                ],
            );
            let install = build_install(
                agent,
                InstallationId(nonce.0),
                registry_reservation,
                name,
                None,
                constructor,
                &package,
            )?;
            let (credential, sequence) = super::local_create::discover_credential(
                &operation.join("query"),
                address,
                operator,
                authority,
            )?;
            let descriptor = discover_agent(address, operator, authority, credential.head, agent)?;
            anyhow::ensure!(
                descriptor.identity.profile == AgentProfile::Local
                    && descriptor.identity.transition_producer
                        == ProducerId::of_public_key(&node_public),
                "target is not a Local Agent of this node"
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expires = now
                .checked_add(3600)
                .ok_or_else(|| anyhow::anyhow!("validity overflow"))?;
            let bytes = prepare(
                operator,
                authority,
                &descriptor,
                install,
                package,
                sequence,
                now.saturating_sub(60),
                expires,
            )?
            .encode();
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let (install, call, _) = LocalInstallSubmission::decode(&request)
        .map_err(|error| anyhow::anyhow!("invalid retained Install: {error:?}"))?
        .into_parts();
    anyhow::ensure!(
        install.installation_id.0 == nonce.0
            && call.authority == authority
            && call.managed.space == space
            && call.managed.agent == agent
            && call.managed.owner == identity.principal()
            && call.principal == identity.principal()
            && call.credential == identity.credential()
            && call.managed.transition_producer == ProducerId::of_public_key(&node_public),
        "retained Install differs from selected Space, Agent, operator or node"
    );
    drop(store);
    let acknowledgement = submit_retained(&request_root, address)?;
    let mut store = CleanLocalInstallFile::open_or_create(&request_root)?;
    reservation.complete_install(&mut store)?;
    Ok(acknowledgement)
}

/// Build the exact actor entry from admitted artifacts. IDs must already be
/// reserved by the caller; this function does not allocate or publish them.
pub(crate) fn build_install(
    agent: vos::agent::sdk::AgentId,
    installation_id: vos::agent::sdk::InstallationId,
    registry_reservation: vos::agent::sdk::Hash,
    name: String,
    parent: Option<vos::agent::sdk::ActorId>,
    data: Option<Vec<u8>>,
    package: &vos::agent::package_admission::AdmittedActorPackage,
) -> anyhow::Result<vos::agent::sdk::InstallActor> {
    use vos::agent::sdk::{
        ActorEntry, ActorId, BlobRef, InstallActor, InstallationData, ManagementRequest,
    };
    anyhow::ensure!(
        agent != vos::agent::sdk::AgentId::ZERO && parent != Some(ActorId::ZERO),
        "invalid target Agent"
    );
    let schema = vos::agent::sdk::schema::decode(package.state_lane_schema_bytes())
        .map_err(|error| anyhow::anyhow!("invalid actor schema: {error:?}"))?;
    anyhow::ensure!(
        data.is_some() == schema.requires_installation_data(),
        "constructor data presence differs from the actor's constructor contract"
    );
    let installation_data = data.map(|bytes| InstallationData {
        reference: BlobRef::of_bytes(&bytes),
        bytes,
    });
    let actor = match parent {
        Some(parent) => ActorId::owned_child(parent, &name),
        None => ActorId::top_level(agent, &name),
    };
    let constructor_abi = schema
        .constructor_abi()
        .map_err(|error| anyhow::anyhow!("constructor ABI: {error:?}"))?;
    let state_layout = schema
        .state_layout_hash()
        .map_err(|error| anyhow::anyhow!("state layout: {error:?}"))?;
    let entry = ActorEntry {
        actor,
        name,
        parent,
        deployment: package.deployment(),
        program: package.program(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi,
        installation_data: installation_data
            .as_ref()
            .map(|data| data.reference.clone()),
        state_layout,
        lanes: package.requirements().lanes,
        suspended: false,
    };
    let install = InstallActor {
        installation_id,
        registry_reservation,
        entry,
        producer: package.producer(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi,
        installation_data,
        state_layout,
        contract: package.manifest().contract,
        requirements: package.requirements(),
    };
    anyhow::ensure!(
        ManagementRequest::Install(Box::new(install.clone())).is_valid(),
        "invalid actor installation"
    );
    Ok(install)
}

/// Discovery must agree with the head used for credential sequence selection.
/// These response-bound local pages are not a management receipt or finality.
pub(crate) fn discover_agent(
    address: std::net::SocketAddr,
    operator: &libp2p::identity::Keypair,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    head: vos::agent::sdk::authority::AuthorityProjectionHead,
    agent: vos::agent::sdk::AgentId,
) -> anyhow::Result<vos::agent::sdk::AgentDescriptor> {
    discover_agent_with(operator, authority, head, agent, |query| {
        let bytes = query
            .encode()
            .map_err(|error| anyhow::anyhow!("encode inventory query: {error:?}"))?;
        super::local_create::post_binary(
            address,
            "/__agents/inventory",
            200,
            &bytes,
            vos::agent::sdk::MAX_INVOCATION_REPLY_BYTES,
        )
    })
}

/// Start strictly before this Agent, after every possible row of its predecessor.
fn descriptor_lookup_cursor(
    agent: vos::agent::sdk::AgentId,
) -> Option<vos::agent::sdk::authority::AuthorityInventoryCursor> {
    use vos::agent::sdk::authority::{AuthorityInventoryCursor, AuthorityInventoryPosition};
    let mut previous = agent.0;
    for byte in previous.iter_mut().rev() {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    (previous != [0; 32]).then_some(AuthorityInventoryCursor {
        agent: vos::agent::sdk::AgentId(previous),
        position: AuthorityInventoryPosition::Actor(vos::agent::sdk::ActorId([0xff; 32])),
    })
}

fn discover_agent_with(
    operator: &libp2p::identity::Keypair,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    head: vos::agent::sdk::authority::AuthorityProjectionHead,
    agent: vos::agent::sdk::AgentId,
    mut query: impl FnMut(
        &vos::agent::sdk::authority::AuthorityProjectionQuery,
    ) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<vos::agent::sdk::AgentDescriptor> {
    use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
    use vos::agent::sdk::authority::{
        AuthorityCredentialKind, AuthorityCredentialStatus, AuthorityInventoryEntry,
        AuthorityInventoryProjectionPage, AuthorityProjectionSelector,
        MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES,
    };
    anyhow::ensure!(
        agent != vos::agent::sdk::AgentId::ZERO && head.is_valid(),
        "invalid Agent or credential head"
    );
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    let mut signer =
        super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(
            operator.clone(),
        )?;
    let mut after = descriptor_lookup_cursor(agent);
    let mut row: Option<vos::agent::sdk::authority::AuthorityAgentProjection> = None;
    let mut replicas = Vec::new();
    let mut claims: Option<vos::agent::sdk::authority::AuthorityCredentialProjection> = None;
    loop {
        let request = signer.authenticate(
            authority,
            AuthorityProjectionSelector::Inventory {
                after,
                limit: MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES as u16,
                known_head: None,
            },
        )?;
        let page = AuthorityInventoryProjectionPage::decode(&query(&request)?)
            .map_err(|error| anyhow::anyhow!("invalid targeted Agent inventory: {error:?}"))?;
        anyhow::ensure!(
            page.credential.query == request
                && page.credential.head == head
                && page.credential.principal == identity.principal()
                && page.credential.status == AuthorityCredentialStatus::Active
                && page.credential.kind == AuthorityCredentialKind::Api
                && !page.unchanged,
            "Agent inventory differs from exact query, active credential or head"
        );
        let mut comparable = page.credential.clone();
        if let Some(previous) = &claims {
            comparable.query = previous.query.clone();
            anyhow::ensure!(
                &comparable == previous,
                "credential claims changed across inventory pages"
            );
        } else {
            claims = Some(comparable);
        }
        for entry in page.entries {
            match entry {
                AuthorityInventoryEntry::Agent(found)
                    if found.identity.agent == agent && row.is_none() =>
                {
                    row = Some(found);
                }
                AuthorityInventoryEntry::Replica {
                    agent: owner,
                    replica,
                } if owner == agent => {
                    let expected = row
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("replica precedes Agent descriptor"))?;
                    replicas.push(replica);
                    anyhow::ensure!(
                        replicas.len() <= usize::from(expected.replica_count),
                        "replica inventory overflow"
                    );
                }
                _ => {
                    let expected = row
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Agent absent from Authority inventory"))?;
                    anyhow::ensure!(
                        replicas.len() == usize::from(expected.replica_count),
                        "incomplete Agent roster"
                    );
                    break;
                }
            }
        }
        let expected = row
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent absent from Authority inventory"))?;
        if replicas.len() == usize::from(expected.replica_count) {
            return row
                .unwrap()
                .reconstruct_descriptor(replicas)
                .map_err(|error| {
                    anyhow::anyhow!("incomplete or inconsistent Agent descriptor: {error:?}")
                });
        }
        after = Some(
            page.next
                .ok_or_else(|| anyhow::anyhow!("incomplete Agent roster"))?,
        );
    }
}

/// Prepare exact bytes using an already allocated credential sequence and
/// independently selected descriptor/Authority. No clock or nonce is generated.
pub(crate) fn prepare(
    operator: &libp2p::identity::Keypair,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    descriptor: &vos::agent::sdk::AgentDescriptor,
    install: vos::agent::sdk::InstallActor,
    package: vos::agent::package_admission::AdmittedActorPackage,
    sequence: std::num::NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalInstallSubmission> {
    use vos::agent::sdk::authority::{AuthorityCredentialCall, ManagedAgentTarget};
    use vos::agent::sdk::{InvocationId, ManagementRequest};
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.validate().is_ok()
            && descriptor.identity.owner == identity.principal()
            && descriptor.authority == authority.binding
            && descriptor.identity.space == authority.space,
        "Local Install descriptor differs from selected operator/Authority"
    );
    package
        .envelope()
        .require_compatible_with(descriptor.runtime_contract, descriptor.capabilities)
        .map_err(|error| anyhow::anyhow!("unsupported actor requirements: {error:?}"))?;
    let managed = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let request = ManagementRequest::Install(Box::new(install.clone()));
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
            .ok_or_else(|| anyhow::anyhow!("invalid Install plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Install signature must be Ed25519"))?;
    LocalInstallSubmission::new(install, call, package)
        .map_err(|error| anyhow::anyhow!("invalid signed Local Install: {error:?}"))
}

pub(crate) fn verify_acknowledgement(
    request: &[u8],
    response: &[u8],
) -> anyhow::Result<ManagementApplicationAck> {
    let submission = LocalInstallSubmission::decode(request)
        .map_err(|error| anyhow::anyhow!("invalid retained Local Install: {error:?}"))?;
    let (_, call, _) = submission.into_parts();
    super::local_create::verify_call_acknowledgement(&call, response)
}

pub(crate) fn submit_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<ManagementApplicationAck> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "plaintext Local Install requires a nonzero loopback endpoint"
    );
    let mut store = super::clean_store::CleanLocalInstallFile::open_or_create(root)?;
    let request = store
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("no retained Local Install request"))?;
    let result = (|| {
        if let Some(bytes) = store.load_acknowledgement()? {
            return verify_acknowledgement(&request, &bytes);
        }
        let response = super::local_create::post_binary(
            address,
            "/__agents/local/install",
            201,
            &request,
            vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
        )?;
        let acknowledgement = verify_acknowledgement(&request, &response)?;
        store.publish_acknowledgement(&response)?;
        Ok(acknowledgement)
    })();
    result.map_err(super::local_create::retained_submission_error)
}

pub(crate) fn run_submit(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let acknowledgement = submit_retained(root, address)?;
    print_acknowledgement(&acknowledgement)
}

fn print_acknowledgement(acknowledgement: &ManagementApplicationAck) -> anyhow::Result<()> {
    if crate::output::is_json() {
        crate::output::print_json(&serde_json::json!({
            "agent": hex::encode(acknowledgement.managed.agent.0),
            "acknowledgement": hex::encode(acknowledgement.encode()
                .map_err(|error| anyhow::anyhow!("encode acknowledgement: {error:?}"))?),
        }));
    } else {
        println!(
            "Local Agent {}: verified installation acknowledgement",
            hex::encode(acknowledgement.managed.agent.0)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use vos::agent::sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
        ManagementApproval,
    };
    use vos::agent::sdk::{Hash, ManagementReply};

    fn fixture() -> (Vec<u8>, ManagementApplicationAck, libp2p::identity::Keypair) {
        fixture_with_target(false)
    }

    fn fixture_with_target(
        native: bool,
    ) -> (Vec<u8>, ManagementApplicationAck, libp2p::identity::Keypair) {
        let (operator, mut authority, mut descriptor, runtime) =
            super::super::local_create::tests::fixture();
        if native {
            let identity =
                super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
            let package = crate::bundled::root_signed_actor_package(
                crate::bundled::system_authority_package_template(),
                "system-authority",
                &operator,
            )
            .unwrap();
            authority = super::super::clean_startup::derive_system_authority_target(
                descriptor.identity.space,
                identity.raw_public_key(),
                &runtime,
                &package,
            )
            .unwrap()
            .0;
            descriptor.authority = authority.binding;
            descriptor.identity.transition_producer =
                vos::agent::sdk::ProducerId::of_public_key(&[0x77; 32]);
        }
        let package = vos::agent::package_admission::admit_actor_package(include_bytes!(
            "../../../blobs/system_catalog.vos"
        ))
        .unwrap();
        let install = Box::new(
            build_install(
                descriptor.identity.agent,
                vos::agent::sdk::InstallationId([0x51; 32]),
                Hash([0x52; 32]),
                "catalog".into(),
                None,
                Some(vec![1]),
                &package,
            )
            .unwrap(),
        );
        let submission = prepare(
            &operator,
            authority,
            &descriptor,
            *install.clone(),
            package.clone(),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap();
        let request = submission.encode();
        assert_eq!(
            prepare(
                &operator,
                authority,
                &descriptor,
                *install.clone(),
                package,
                NonZeroU64::new(2).unwrap(),
                10,
                30
            )
            .unwrap()
            .encode(),
            request
        );
        let (_, call, _) = submission.into_parts();
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
                actor: Some(install.entry.actor),
                actor_deployment: Some(install.entry.deployment),
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
            application: ManagementReply::Installed(install.entry.clone()),
            reopened_state: Hash([11; 32]),
            applied_at: 20,
            signature: [0; 64],
        };
        ack.signature = operator
            .sign(&ack.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        (request, ack, operator)
    }

    #[test]
    #[ignore = "requires the disposable native-denial-smoke daemon and explicit Install smoke environment"]
    fn real_daemon_managed_install_and_exact_resume() {
        use super::super::clean_store::{CleanCredentialReservation, CleanLocalCreateRequestFile};
        let ctor = std::path::PathBuf::from(
            std::env::var("VOSX_INSTALL_SMOKE_CONSTRUCTOR")
                .expect("explicit disposable constructor path"),
        );
        let agent = vos::agent::sdk::AgentId(
            hex::decode(std::env::var("VOSX_INSTALL_SMOKE_AGENT").unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let (data, space, node_public, address) =
            super::super::local_create::resolve_local_space("native-denial-smoke", None).unwrap();
        assert!(
            data.to_string_lossy().contains("native-denial-head-reuse."),
            "disposable campaign only"
        );
        assert_eq!(ctor.parent(), data.parent());
        let operator = crate::identity::load_existing().unwrap();
        let package_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("blobs/system_catalog.vos");
        let package = vos::agent::package_admission::admit_actor_package(
            &std::fs::read(&package_path).unwrap(),
        )
        .unwrap();
        let name = std::env::var("VOSX_INSTALL_SMOKE_NAME")
            .unwrap_or_else(|_| "install-smoke-catalog".into());
        let resume = std::env::var_os("VOSX_INSTALL_SMOKE_RESUME").is_some();
        if !resume {
            assert!(
                !ctor.exists(),
                "fresh Install constructor artifact required"
            );
            let identity =
                super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
            let mut reservation = CleanCredentialReservation::open_or_create(
                &data.join("agent-client/credentials"),
                space,
                identity.credential(),
            )
            .unwrap();
            let (nonce, status) = reservation.current().unwrap().unwrap();
            assert_eq!(
                status,
                super::super::clean_store::CredentialReservationStatus::Completed
            );
            let root = data
                .join("agent-client/operations")
                .join(format!(
                    "{}-{}",
                    hex::encode(identity.credential().0),
                    hex::encode(nonce.0)
                ))
                .join("request");
            let previous = if root.join("local-install.request").exists() {
                let request =
                    super::super::clean_store::CleanLocalInstallFile::open_or_create(&root)
                        .unwrap()
                        .load_request()
                        .unwrap()
                        .unwrap();
                LocalInstallSubmission::decode(&request)
                    .unwrap()
                    .into_parts()
                    .1
            } else {
                let request = CleanLocalCreateRequestFile::open_or_create(&root)
                    .unwrap()
                    .load()
                    .unwrap()
                    .unwrap();
                vos::agent::local_lifecycle::LocalCreateSubmission::decode(&request)
                    .unwrap()
                    .into_parts()
                    .1
            };
            assert_eq!(previous.managed.agent, agent);
            assert_eq!(previous.managed.space, space);
            let binding = previous.authority.binding;
            let configuration = system_catalog::SystemCatalogConfiguration {
                space: space.0,
                system_agent: agent.0,
                system_runtime_deployment: previous.managed.runtime_deployment.0,
                actor: vos::agent::sdk::ActorId::top_level(agent, &name).0,
                deployment: package.deployment().0,
                program: package.program().0,
                authority: system_catalog::CatalogAuthorityState {
                    policy: binding.policy.0,
                    issuer: system_catalog::CatalogIssuerState {
                        principal: binding.issuer.principal.0,
                        actor: binding.issuer.actor.0,
                        deployment: binding.issuer.deployment.0,
                        program: binding.issuer.program.0,
                        producer: binding.issuer.producer.0,
                    },
                    public_key: binding.public_key,
                    initial_epoch: binding.initial_epoch,
                },
            };
            assert!(configuration.is_valid());
            std::fs::write(&ctor, configuration.encode()).unwrap();
        }
        let mut args = InstallLocalArgs {
            space: "native-denial-smoke".into(),
            agent: hex::encode(agent.0),
            package: package_path,
            name: Some(name.into()),
            constructor_data: Some(ctor),
            http: Some(address),
            resume,
            max_program_bytes: vos::agent::sdk::STANDARD_ACTOR_PROGRAM_BYTES as u32,
        };
        let mut completed = None;
        for attempt in 0..4 {
            match install_local(&data, address, &operator, space, node_public, agent, &args) {
                Ok(ack) => {
                    completed = Some(ack);
                    break;
                }
                Err(error) => eprintln!("Install attempt {attempt}: {error}"),
            }
            args.resume = true;
        }
        let acknowledgement =
            completed.expect("native Install must complete within bounded identical retries");
        args.resume = true;
        assert_eq!(
            install_local(&data, address, &operator, space, node_public, agent, &args).unwrap(),
            acknowledgement
        );
        assert!(matches!(
            acknowledgement.application,
            ManagementReply::Installed(_)
        ));
        eprintln!("native Install and exact retained resume passed");
    }

    #[test]
    fn fresh_install_command_parses_explicit_inputs_and_resume() {
        use clap::Parser as _;
        let parsed = crate::Cli::try_parse_from([
            "vosx",
            "space",
            "install-local-actor",
            "demo",
            &hex::encode([0x11; 32]),
            "actor.vos",
            "--name",
            "worker",
            "--constructor-data",
            "constructor.bin",
            "--http",
            "127.0.0.1:8080",
            "--resume",
        ])
        .unwrap();
        let Some(crate::Command::Space {
            command: super::super::SpaceCommand::InstallLocalActor(args),
        }) = parsed.command
        else {
            panic!("wrong command");
        };
        assert_eq!(args.space, "demo");
        assert_eq!(args.package, std::path::PathBuf::from("actor.vos"));
        assert_eq!(args.name.as_deref(), Some("worker"));
        assert_eq!(
            args.constructor_data,
            Some(std::path::PathBuf::from("constructor.bin"))
        );
        assert_eq!(args.http, Some("127.0.0.1:8080".parse().unwrap()));
        assert!(args.resume);
        assert!(
            crate::Cli::try_parse_from(["vosx", "space", "install-local-actor", "demo"]).is_err()
        );
    }

    #[test]
    fn managed_resume_uses_retained_bytes_and_finishes_reserved_delivery() {
        use super::super::clean_store::{
            CleanCredentialReservation, CleanLocalInstallFile, CredentialReservationStatus,
            ensure_private_directory,
        };
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, operator) = fixture_with_target(true);
        let (install, call, _) = LocalInstallSubmission::decode(&request)
            .unwrap()
            .into_parts();
        let nonce = Hash(install.installation_id.0);
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("vosx-managed-install-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let root = directory.join("agent-client");
        let _root = ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        reservation.reserve(nonce).unwrap();
        drop(reservation);
        let operations = root.join("operations");
        let _operations = ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(call.credential.0),
            hex::encode(nonce.0)
        ));
        let _operation = ensure_private_directory(&operation).unwrap();
        let mut delivery =
            CleanLocalInstallFile::open_or_create(operation.join("request")).unwrap();
        delivery.publish_request(&request).unwrap();
        delivery
            .publish_acknowledgement(&ack.encode().unwrap())
            .unwrap();
        drop(delivery);
        let args = InstallLocalArgs {
            space: "unused-index-name".into(),
            agent: hex::encode(call.managed.agent.0),
            package: directory.join("missing-package"),
            name: Some("changed-and-ignored".into()),
            constructor_data: Some(directory.join("missing-constructor")),
            http: None,
            resume: true,
            max_program_bytes: vos::agent::sdk::STANDARD_ACTOR_PROGRAM_BYTES as u32,
        };
        let address = "127.0.0.1:1".parse().unwrap();
        assert!(
            install_local(
                &directory,
                address,
                &operator,
                call.managed.space,
                [0x78; 32],
                call.managed.agent,
                &args
            )
            .is_err()
        );
        assert!(
            install_local(
                &directory,
                address,
                &operator,
                call.managed.space,
                [0x77; 32],
                vos::agent::sdk::AgentId([0x78; 32]),
                &args
            )
            .is_err()
        );
        assert_eq!(
            install_local(
                &directory,
                address,
                &operator,
                call.managed.space,
                [0x77; 32],
                call.managed.agent,
                &args
            )
            .unwrap(),
            ack
        );
        assert_eq!(
            install_local(
                &directory,
                address,
                &operator,
                call.managed.space,
                [0x77; 32],
                call.managed.agent,
                &args
            )
            .unwrap(),
            ack
        );
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Completed))
        );
        drop(reservation);
        assert!(!args.package.exists());
        drop((_operation, _operations, _claims, _root));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn actor_builder_binds_target_and_package_and_requires_constructor_data() {
        use vos::agent::sdk::{ActorId, InstallationId};
        let (_, _, descriptor, _) = super::super::local_create::tests::fixture();
        let package = vos::agent::package_admission::admit_actor_package(include_bytes!(
            "../../../blobs/system_catalog.vos"
        ))
        .unwrap();
        let build = |name: &str, parent, data| {
            build_install(
                descriptor.identity.agent,
                InstallationId([0x41; 32]),
                Hash([0x42; 32]),
                name.into(),
                parent,
                data,
                &package,
            )
        };
        assert!(build("catalog", None, None).is_err());
        let first = build("catalog", None, Some(vec![1])).unwrap();
        assert_eq!(first, build("catalog", None, Some(vec![1])).unwrap());
        assert_eq!(
            first.entry.actor,
            ActorId::top_level(descriptor.identity.agent, "catalog")
        );
        assert_eq!(first.entry.package, *package.package_ref());
        assert_eq!(first.entry.deployment, package.deployment());
        assert_eq!(first.entry.program, package.program());
        let parent = ActorId([0x43; 32]);
        let child = build("child", Some(parent), Some(vec![1])).unwrap();
        assert_eq!(child.entry.actor, ActorId::owned_child(parent, "child"));
        assert!(build("", None, Some(vec![1])).is_err());
        assert!(build("child", Some(ActorId::ZERO), Some(vec![1])).is_err());
        assert_ne!(
            first.entry.installation_data,
            build("catalog", None, Some(vec![2]))
                .unwrap()
                .entry
                .installation_data
        );
    }

    #[test]
    fn descriptor_lookup_cursor_covers_id_boundaries() {
        use vos::agent::sdk::AgentId;
        let mut minimum = [0; 32];
        minimum[31] = 1;
        assert_eq!(descriptor_lookup_cursor(AgentId(minimum)), None);
        let mut next = minimum;
        next[31] = 2;
        assert_eq!(
            descriptor_lookup_cursor(AgentId(next)).unwrap().agent,
            AgentId(minimum)
        );
        let maximum = AgentId([0xff; 32]);
        assert!(descriptor_lookup_cursor(maximum).unwrap().agent < maximum);
        for carry_at in 0..31 {
            let mut target = [0; 32];
            target[carry_at] = 1;
            let mut previous = [0; 32];
            previous[carry_at + 1..].fill(0xff);
            let cursor = descriptor_lookup_cursor(AgentId(target)).unwrap();
            assert_eq!(cursor.agent, AgentId(previous));
            assert_eq!(
                cursor.position,
                vos::agent::sdk::authority::AuthorityInventoryPosition::Actor(
                    vos::agent::sdk::ActorId([0xff; 32])
                )
            );
        }
    }

    #[test]
    fn descriptor_discovery_requires_exact_query_head_and_complete_roster() {
        use vos::agent::sdk::authority::{
            AuthorityAgentProjection, AuthorityBuiltinRole, AuthorityCredentialKind,
            AuthorityCredentialProjection, AuthorityCredentialStatus, AuthorityInventoryEntry,
            AuthorityInventoryProjectionPage, AuthorityProjectionHead, AuthorityProjectionSelector,
        };
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let identity =
            super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
        let head = AuthorityProjectionHead {
            state_revision: NonZeroU64::new(1).unwrap(),
            epoch: NonZeroU64::new(1).unwrap(),
            authorization_sequence: NonZeroU64::new(1).unwrap(),
            administration_generation: NonZeroU64::new(1).unwrap(),
            state_commitment: Hash([0x31; 32]),
        };
        let row = AuthorityAgentProjection {
            identity: descriptor.identity.clone(),
            creation_nonce: descriptor.creation_nonce,
            authority: descriptor.authority,
            private_recovery: descriptor.private_recovery,
            runtime_package: descriptor.runtime_package.clone(),
            runtime_contract: descriptor.runtime_contract,
            capabilities: descriptor.capabilities,
            replica_count: descriptor.replicas.len() as u16,
            replica_generation: vos::agent::sdk::replica_set_generation(
                &descriptor.identity,
                descriptor.creation_nonce,
                &descriptor.replicas,
            ),
        };
        for page_size in [1, 64] {
            for mode in 0..9 {
                if mode == 4 && page_size == 64 {
                    continue;
                }
                let mut changed_row = row.clone();
                if mode == 5 {
                    changed_row.replica_generation = Hash([0x34; 32]);
                }
                let mut entries = vec![AuthorityInventoryEntry::Agent(changed_row)];
                entries.extend(descriptor.replicas.iter().cloned().map(|replica| {
                    AuthorityInventoryEntry::Replica {
                        agent: descriptor.identity.agent,
                        replica,
                    }
                }));
                if mode == 3 || mode == 6 {
                    entries.clear();
                }
                if mode == 7 {
                    entries.truncate(1);
                }
                if mode == 8 {
                    entries.remove(0);
                }
                let mut calls = 0;
                let mut offset = 0;
                let result = discover_agent_with(
                    &operator,
                    authority,
                    head,
                    descriptor.identity.agent,
                    |query| {
                        let AuthorityProjectionSelector::Inventory {
                            after, known_head, ..
                        } = query.selector
                        else {
                            panic!("descriptor discovery must use targeted Inventory");
                        };
                        assert_eq!(known_head, None);
                        if calls == 0 {
                            assert_eq!(after, descriptor_lookup_cursor(descriptor.identity.agent));
                        } else {
                            assert_eq!(after, Some(entries[offset - 1].cursor()));
                        }
                        calls += 1;
                        let mut credential = AuthorityCredentialProjection {
                            query: query.clone(),
                            head,
                            principal: identity.principal(),
                            status: AuthorityCredentialStatus::Active,
                            kind: AuthorityCredentialKind::Api,
                            builtin_role: AuthorityBuiltinRole::Admin,
                            management_request_high_water: 0,
                            operation_request_high_water: 0,
                            admin_request_high_water: 0,
                            space_roles: vec![],
                            actor_roles: vec![],
                            capabilities: vec![],
                        };
                        if mode == 1 {
                            credential.head.state_commitment = Hash([0x32; 32]);
                        }
                        if mode == 2 {
                            credential.query.nonce = Hash([0x33; 32]);
                        }
                        if mode == 4 && calls > 1 {
                            credential.operation_request_high_water = 1;
                        }
                        if mode == 6 {
                            credential.status = AuthorityCredentialStatus::Revoked;
                        }
                        let end = (offset + page_size).min(entries.len());
                        let page_entries = entries[offset..end].to_vec();
                        offset = end;
                        let next =
                            (end < entries.len()).then(|| page_entries.last().unwrap().cursor());
                        AuthorityInventoryProjectionPage {
                            credential,
                            unchanged: false,
                            entries: page_entries,
                            next,
                        }
                        .encode()
                        .map_err(|error| anyhow::anyhow!("fixture: {error:?}"))
                    },
                );
                if mode == 0 {
                    assert_eq!(result.unwrap(), descriptor);
                    assert_eq!(calls, entries.len().div_ceil(page_size));
                    if page_size == 64 {
                        assert_eq!(calls, 1);
                    }
                } else {
                    assert!(result.is_err(), "mode {mode}, page size {page_size}");
                }
            }
        }
    }

    #[test]
    fn install_reservation_requires_durable_exact_completion_and_serializes_successors() {
        use super::super::clean_store::{
            CleanCredentialReservation, CleanFileStoreError, CleanLocalInstallFile,
            CredentialReservationStatus, ensure_private_directory,
        };
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, _) = fixture();
        let (install, call, _) = LocalInstallSubmission::decode(&request)
            .unwrap()
            .into_parts();
        let nonce = Hash(install.installation_id.0);
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("vosx-install-reservation-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let claims = directory.join("claims");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        assert!(matches!(
            CleanCredentialReservation::open_or_create(
                &claims,
                call.managed.space,
                call.credential
            ),
            Err(CleanFileStoreError::Busy)
        ));
        assert_eq!(
            reservation.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        let successor = Hash([0x71; 32]);
        assert!(matches!(
            reservation.reserve(successor),
            Err(CleanFileStoreError::RequestConflict)
        ));
        let mut delivery =
            CleanLocalInstallFile::open_or_create(directory.join("request")).unwrap();
        delivery.publish_request(&request).unwrap();
        assert!(reservation.complete_install(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        delivery
            .publish_acknowledgement(&ack.encode().unwrap())
            .unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Completed))
        );
        drop(reservation);
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        assert_eq!(
            reservation.reserve(successor).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(reservation.complete_install(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((successor, CredentialReservationStatus::Pending))
        );
        let mut other = CleanCredentialReservation::open_or_create(
            &claims,
            vos::agent::sdk::SpaceId([0x72; 32]),
            call.credential,
        )
        .unwrap();
        other.reserve(nonce).unwrap();
        assert!(other.complete_install(&mut delivery).is_err());
        drop(other);
        drop(reservation);
        drop(delivery);
        drop(_claims);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn retained_install_transport_preserves_request_and_verifies_before_completion() {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalInstallFile};
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, _) = fixture();
        let encoded = ack.encode().unwrap();
        for (status, content_type, body, success) in [
            (201, "application/octet-stream", encoded.clone(), true),
            (503, "application/octet-stream", encoded.clone(), false),
            (403, "application/octet-stream", encoded.clone(), false),
            (302, "application/octet-stream", encoded.clone(), false),
            (201, "text/plain", encoded.clone(), false),
            (
                201,
                "application/octet-stream",
                encoded[..encoded.len() - 1].to_vec(),
                false,
            ),
        ] {
            let mut nonce = [0; 8];
            getrandom::getrandom(&mut nonce).unwrap();
            let directory =
                std::env::temp_dir().join(format!("vosx-install-http-{}", hex::encode(nonce)));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let root = directory.join("request");
            CleanLocalInstallFile::open_or_create(&root)
                .unwrap()
                .publish_request(&request)
                .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let expected = request.clone();
            let leased = root.clone();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "client did not connect"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                }
                assert!(headers.starts_with(b"POST /__agents/local/install HTTP/1.1\r\n"));
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(received, expected);
                assert!(matches!(
                    CleanLocalInstallFile::open_or_create(&leased),
                    Err(CleanFileStoreError::Busy)
                ));
                write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            });
            let result = submit_retained(&root, address);
            server.join().unwrap();
            assert_eq!(result.is_ok(), success, "status={status}: {result:?}");
            let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
            assert_eq!(store.load_request().unwrap(), Some(request.clone()));
            assert_eq!(
                store.load_acknowledgement().unwrap(),
                success.then(|| encoded.clone())
            );
            drop(store);
            if success {
                assert_eq!(submit_retained(&root, address).unwrap(), ack);
            }
            std::fs::remove_dir_all(&directory).unwrap();
        }
    }

    #[test]
    fn exact_install_acknowledgement_and_immutable_storage() {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalInstallFile};
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, operator) = fixture();
        let response = ack.encode().unwrap();
        assert_eq!(verify_acknowledgement(&request, &response).unwrap(), ack);
        let mut wrong = ack.clone();
        wrong.signature[0] ^= 1;
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        wrong = ack.clone();
        wrong.receipt.signature[0] ^= 1;
        wrong.signature = operator
            .sign(&wrong.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        wrong = ack.clone();
        if let ManagementReply::Installed(entry) = &mut wrong.application {
            entry.suspended = true;
        }
        wrong.signature = operator
            .sign(&wrong.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        assert!(verify_acknowledgement(&request, &response[..response.len() - 1]).is_err());
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let directory =
            std::env::temp_dir().join(format!("vosx-install-client-{}", hex::encode(nonce)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let root = directory.join("request");
        let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert!(matches!(
            CleanLocalInstallFile::open_or_create(&root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.publish_acknowledgement(&response).is_err());
        store.publish_request(&request).unwrap();
        store.publish_request(&request).unwrap();
        let (install, mut call, package) = LocalInstallSubmission::decode(&request)
            .unwrap()
            .into_parts();
        call.request_sequence = NonZeroU64::new(4).unwrap();
        call.invocation = call.expected_invocation();
        call.signature = operator
            .sign(&call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let other_request = LocalInstallSubmission::new(install, call, package)
            .unwrap()
            .encode();
        assert!(matches!(
            store.publish_request(&other_request),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(
            store
                .publish_acknowledgement(&wrong.encode().unwrap())
                .is_err()
        );
        store.publish_acknowledgement(&response).unwrap();
        let mut conflicting = ack.clone();
        conflicting.reopened_state = Hash([12; 32]);
        conflicting.signature = operator
            .sign(&conflicting.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &conflicting.encode().unwrap()).is_ok());
        assert!(matches!(
            store.publish_acknowledgement(&conflicting.encode().unwrap()),
            Err(CleanFileStoreError::RequestConflict)
        ));
        drop(store);
        let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request.clone()));
        assert_eq!(store.load_acknowledgement().unwrap(), Some(response));
        drop(store);
        // Retained verified completion is returned without connecting to a daemon.
        assert_eq!(
            submit_retained(&root, "127.0.0.1:1".parse().unwrap()).unwrap(),
            ack
        );
        std::fs::remove_file(root.join("local-install.request")).unwrap();
        let mut orphaned = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert!(orphaned.load_acknowledgement().is_err());
        assert!(orphaned.publish_request(&request).is_err());
        assert!(!root.join("local-install.request").exists());
        drop(orphaned);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
