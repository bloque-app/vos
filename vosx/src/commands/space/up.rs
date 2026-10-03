//! `space up` — run a known Space's registry and node-local adapters.
//!
//! The clean cutover does not select or instantiate a generic service guest,
//! interpret recipes or invites, or open the retired authority sidecars. Clean
//! Agent ownership is attached separately by the native bootstrap path.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};
use vos::registry::RegistryRef;

use crate::blob_store::{self, BlobHash};
use crate::commands::space::common::{derive_hyperspace_id, registry_replication_id};
use crate::commands::space::{local_config, reconcile};
use crate::spaces_index;

pub struct Args {
    pub query: String,
    pub once: bool,
    pub listen: Vec<String>,
    pub connect: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.query)?;
    if !entry.pending_recipe.is_empty() {
        anyhow::bail!(
            "space '{}' retains a pending legacy recipe; clean cutover will not execute it",
            entry.name,
        );
    }
    if entry.registry_hash.is_empty() {
        anyhow::bail!(
            "space '{}' has no registry hash; recreate it with `vosx space new`",
            entry.name,
        );
    }

    let registry_hash = BlobHash::from_hex(&entry.registry_hash)
        .map_err(|_| anyhow::anyhow!("space registry hash is not 64 hexadecimal characters"))?;
    let registry_elf = blob_store::cache_get(&registry_hash)?.ok_or_else(|| {
        anyhow::anyhow!("registry blob {registry_hash} is absent from the local cache")
    })?;
    let registry_pvm = vos_pvm_compiler::link_elf(&registry_elf)
        .map_err(|error| anyhow::anyhow!("transpile registry ELF: {error:?}"))?;
    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in the local index is not canonical"))?;
    let data_dir = PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!(
            "space data directory does not exist: {}",
            data_dir.display()
        );
    }

    let _space_data_lock = super::space_lock::SpaceDataLock::exclusive(&space_id)?;
    verify_local_genesis(&data_dir, &space_id)?;
    let local = local_config::load(&data_dir)?;
    local_config::validate_local_storage_roots(&data_dir, local.local_agent_storage)?;
    // The selected production format is validated before networking, daemon
    // identity, or either Local root is opened, including candidate builds.
    crate::bundled::system_authority_package_template_for_storage(local.local_agent_storage)?;
    let daemon_keypair = load_daemon_keypair(&data_dir)?;
    let network = build_network_for_daemon(
        entry,
        &local,
        &args.listen,
        &args.connect,
        daemon_keypair.clone(),
    )?;
    let local_prefix = network.local_prefix();

    let mut node =
        VosNode::with_prefix(local_prefix).with_program_blobs_dir(blob_store::cache_dir());
    configure_ingress_attester(&mut node, &daemon_keypair)?;
    let operator_keypair = configure_operator(&mut node)?;
    crate::bundled::prepare_system_packages_for_storage(
        &operator_keypair,
        local.local_agent_storage,
    )?;

    let registry_config = AgentConfig::new(registry_pvm.clone())
        .with_name(vos::node::REGISTRY_AGENT_NAME)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(registry_replication_id(&space_id))
        .with_node_validator(super::common::genesis_node_validator(space_id))
        .persist(&data_dir);
    let registry_id = node.register_at_id(registry_config, ServiceId::REGISTRY);
    let registry = RegistryRef::at(ServiceId::REGISTRY);
    require_boot_registry_handshake(vos::block_on(registry.protocol(&mut &node)))?;
    anchor_space_id(&node, &registry, space_id)?;
    reject_legacy_registry_rows(&node, &registry)?;
    // A joined node has no registry genesis until its peers sync one; its
    // root check then waits for that sync instead of failing closed early.
    let root_pending = vos::block_on(registry.root(&mut &node))
        .map_err(|error| anyhow::anyhow!("read immutable Space root: {error}"))?
        .is_empty()
        && !entry.bootnodes.is_empty();
    if !root_pending {
        require_space_root(&node, &registry, &operator_keypair)?;
    }

    if !entry.hyperspace.is_empty() {
        let replication_id = derive_hyperspace_id(&entry.hyperspace);
        let hyperspace_config = AgentConfig::new(registry_pvm)
            .with_name(vos::node::HYPERSPACE_REGISTRY_AGENT_NAME)
            .with_consistency(Consistency::Crdt)
            .with_replication_id(replication_id)
            .persist(&data_dir);
        node.register_at_id(hyperspace_config, ServiceId::HYPERSPACE_REGISTRY);
    }

    node.attach_network(network);
    if root_pending {
        // Peer DAG nodes were already checked against this Space's genesis
        // by the registry's node validator before they were merged.
        wait_for_synced_space_root(&node, &registry, &operator_keypair)?;
    }
    #[cfg(target_os = "linux")]
    super::clean_startup::start_clean_system_agent(
        &mut node,
        &data_dir,
        space_id,
        &operator_keypair,
        &daemon_keypair,
        local.local_agent_storage,
        local.system_bootstrap_bundle.as_deref(),
    )?;
    let extension_caps = register_extensions_from_local(
        &mut node,
        &local,
        &data_dir,
        local_prefix,
        &space_id,
        Some(&operator_keypair),
    )?;
    register_http_ingress_from_local(&mut node, &local)?;
    register_ssh_ingress_from_local(&mut node, &local, &data_dir)?;
    publish_endpoint(&node, &data_dir, local_prefix, extension_caps)?;
    #[cfg(target_os = "linux")]
    let recovering = node.ingress_handle().clean_agent_recovering();
    #[cfg(not(target_os = "linux"))]
    let recovering = false;
    if recovering {
        tracing::warn!(space = %entry.name, "Space daemon recovering; exact retained authorization only, not ready");
    } else {
        tracing::info!(space = %entry.name, registry = %registry_id, "Space daemon ready");
    }

    if args.once {
        node.run();
    } else {
        crate::shutdown::install(node.shutdown_handle());
        node.run_forever();
    }

    let results = cleanup_endpoint_after_collect(
        &data_dir,
        node.collect_checked()
            .map_err(|error| anyhow::anyhow!("Agent host shutdown failed: {error}")),
    )?;
    let mut panics = 0;
    for result in &results {
        panics += result.panics;
        if let Some(error) = &result.error {
            tracing::error!(agent = %result.id, "{error}");
        }
    }
    if panics != 0 {
        anyhow::bail!("{panics} PVM panics");
    }
    Ok(())
}

pub(crate) fn load_daemon_keypair(data_dir: &Path) -> anyhow::Result<libp2p::identity::Keypair> {
    let key_path = data_dir.join("node.key");
    let bytes = crate::secure_file::read_owner_only_optional(&key_path, 4 * 1024)?
        .ok_or_else(|| anyhow::anyhow!("node identity does not exist: {}", key_path.display()))?;
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
        .map_err(|error| anyhow::anyhow!("decode {}: {error}", key_path.display()))?;
    if keypair.key_type() != libp2p::identity::KeyType::Ed25519 {
        anyhow::bail!("node identity must be Ed25519: {}", key_path.display());
    }
    let canonical = keypair
        .to_protobuf_encoding()
        .map_err(|error| anyhow::anyhow!("canonicalize {}: {error}", key_path.display()))?;
    if canonical != bytes {
        anyhow::bail!("node identity is not canonical: {}", key_path.display());
    }
    Ok(keypair)
}

fn verify_local_genesis(data_dir: &Path, space_id: &[u8; 32]) -> anyhow::Result<()> {
    let registry_db = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
    if !registry_db.exists() {
        return Ok(());
    }
    match super::verify::verify_with_timeout(&registry_db, space_id, std::time::Duration::ZERO)? {
        super::verify::VerifyOutcome::Verified { genesis_cid } => {
            tracing::info!(root = %hex::encode(genesis_cid), "registry genesis verified");
            Ok(())
        }
        super::verify::VerifyOutcome::NoGenesisYet => {
            tracing::warn!("registry has no genesis event yet; verification waits for sync");
            Ok(())
        }
        super::verify::VerifyOutcome::Mismatch {
            derived,
            advertised,
            ..
        } => anyhow::bail!(
            "registry genesis derives Space {}, but the local entry advertises {}",
            hex::encode(derived),
            hex::encode(advertised),
        ),
    }
}

fn configure_ingress_attester(
    node: &mut VosNode,
    daemon_keypair: &libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    let peer = libp2p::PeerId::from(daemon_keypair.public());
    let node_id = vos::service::NodeId::of_authenticated_peer(&peer.to_bytes());
    let signer = daemon_keypair.clone();
    node.set_ingress_node_attester(vos::agent::sdk::NodeId(node_id.0), move |canonical| {
        let signature = signer.sign(canonical).ok()?;
        signature.as_slice().try_into().ok()
    })
    .map_err(|error| anyhow::anyhow!("configure ingress node attester: {error}"))
}

fn configure_operator(node: &mut VosNode) -> anyhow::Result<libp2p::identity::Keypair> {
    let keypair = crate::identity::load_or_create()
        .map_err(|error| anyhow::anyhow!("load required Space operator identity: {error}"))?;
    let peer = libp2p::PeerId::from(keypair.public()).to_bytes();
    node.set_operator_peer(peer.clone());
    let signer = keypair.clone();
    node.set_operator_signer(move |canonical| {
        let signature: [u8; 64] = signer.sign(canonical).ok()?.as_slice().try_into().ok()?;
        Some(vos::registry::pack_auth(&peer, &signature))
    });
    Ok(keypair)
}

fn require_space_root(
    node: &VosNode,
    registry: &RegistryRef,
    operator: &libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    let root = vos::block_on(registry.root(&mut &*node))
        .map_err(|error| anyhow::anyhow!("read immutable Space root: {error}"))?;
    let expected = operator.public().to_peer_id().to_bytes();
    if root != expected {
        anyhow::bail!(
            "local operator identity is not this Space's immutable root; clean system-Agent bootstrap cannot use an ambient substitute"
        );
    }
    Ok(())
}

/// Bound on how long a joined node waits for its bootnodes to deliver the
/// registry genesis before the root check fails closed.
const JOIN_REGISTRY_SYNC_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

fn wait_for_synced_space_root(
    node: &VosNode,
    registry: &RegistryRef,
    operator: &libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + JOIN_REGISTRY_SYNC_WINDOW;
    loop {
        let root = vos::block_on(registry.root(&mut &*node))
            .map_err(|error| anyhow::anyhow!("read immutable Space root: {error}"))?;
        if !root.is_empty() {
            return require_space_root(node, registry, operator);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "registry genesis did not sync from the bootnodes within {}s",
                JOIN_REGISTRY_SYNC_WINDOW.as_secs()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn require_boot_registry_handshake(
    result: Result<vos::registry::RegistryProtocol, vos::actors::client::ClientError>,
) -> anyhow::Result<()> {
    result
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("registry protocol handshake failed: {error}"))
}

fn anchor_space_id(
    node: &VosNode,
    registry: &RegistryRef,
    space_id: [u8; 32],
) -> anyhow::Result<()> {
    match vos::block_on(registry.set_space_id(&mut &*node, space_id.to_vec()))
        .map_err(|error| anyhow::anyhow!("anchor registry Space id: {error}"))?
    {
        vos::registry::Status::Ok | vos::registry::Status::Forbidden => {}
        status => anyhow::bail!("registry refused Space-id anchor: {status}"),
    }
    let observed = vos::block_on(registry.space_id(&mut &*node))
        .map_err(|error| anyhow::anyhow!("read registry Space-id anchor: {error}"))?;
    if observed.as_slice() != space_id {
        anyhow::bail!("registry Space-id anchor does not match the local Space");
    }
    Ok(())
}

fn reject_legacy_registry_rows(node: &VosNode, registry: &RegistryRef) -> anyhow::Result<()> {
    let rows = vos::block_on(registry.agents_all(&mut &*node))
        .map_err(|error| anyhow::anyhow!("inspect registry compatibility rows: {error}"))?;
    if let Some(row) = rows.first() {
        anyhow::bail!(
            "space registry contains retired service installation '{}'; clean cutover will not execute it",
            row.instance_name,
        );
    }
    Ok(())
}

fn build_network_for_daemon(
    entry: &spaces_index::SpaceEntry,
    local: &local_config::LocalConfig,
    listen_override: &[String],
    connect_extra: &[String],
    keypair: libp2p::identity::Keypair,
) -> anyhow::Result<vos::network::Network> {
    let parse = |value: &str, kind: &str| {
        libp2p::Multiaddr::from_str(value)
            .map_err(|error| anyhow::anyhow!("invalid {kind} multiaddr '{value}': {error}"))
    };
    let listen_source = if listen_override.is_empty() {
        &local.listen
    } else {
        listen_override
    };
    let mut listen = listen_source
        .iter()
        .map(|value| parse(value, "listen"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if listen.is_empty() {
        listen.push("/ip4/127.0.0.1/tcp/0".parse().expect("literal multiaddr"));
    }
    let mut bootstrap = entry
        .bootnodes
        .iter()
        .map(|value| parse(value, "bootnode"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for value in connect_extra {
        bootstrap.push(parse(value, "connect")?);
    }
    let peer = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer);
    tracing::info!(%peer, prefix = format_args!("{local_prefix:#06x}"), "node identity loaded");
    Ok(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap,
        auto_dial_mdns: std::env::var("VOSX_DISABLE_MDNS").is_err(),
    }))
}

fn register_extensions_from_local(
    node: &mut VosNode,
    local: &local_config::LocalConfig,
    data_dir: &Path,
    prefix: u16,
    space_id: &[u8; 32],
    operator: Option<&libp2p::identity::Keypair>,
) -> anyhow::Result<Vec<super::endpoint::ExtensionCaps>> {
    let registry = RegistryRef::at(ServiceId::new(prefix, ServiceId::REGISTRY.local_id()));
    let known_names = local
        .extensions
        .iter()
        .map(|extension| extension.name.clone())
        .chain(std::iter::once("space-registry".to_string()))
        .collect::<HashSet<_>>();
    local
        .extensions
        .iter()
        .map(|extension| {
            let definition = reconcile::ExtensionDef {
                name: extension.name.clone(),
                path: extension.path.clone(),
                init: extension.init.clone(),
                intra_caps: extension.intra_caps.clone(),
                tick_ms: extension.tick_ms,
            };
            let caps = reconcile::register_extension(
                node,
                &registry,
                &definition,
                data_dir,
                prefix,
                space_id,
                &known_names,
                operator,
            )?;
            Ok(super::endpoint::ExtensionCaps {
                name: extension.name.clone(),
                caps,
            })
        })
        .collect()
}

fn register_http_ingress_from_local(
    node: &mut VosNode,
    local: &local_config::LocalConfig,
) -> anyhow::Result<()> {
    let mut names = BTreeSet::new();
    for listener in &local.ingress.http {
        validate_ingress_name("HTTP", &listener.name)?;
        if !names.insert(listener.name.as_str()) {
            anyhow::bail!("duplicate HTTP ingress name '{}'", listener.name);
        }
        let listen = listener
            .listen
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid HTTP ingress address: {error}"))?;
        let tls = match (&listener.tls_cert, &listener.tls_key) {
            (Some(cert), Some(key)) => Some(vos::ingress::HttpTlsConfig {
                cert: cert.into(),
                key: key.into(),
            }),
            (None, None) => None,
            _ => anyhow::bail!("HTTP ingress '{}' requires both TLS files", listener.name),
        };
        node.add_http_ingress(vos::ingress::HttpIngressConfig {
            name: listener.name.clone(),
            listen,
            tls,
            max_connections: listener.max_connections,
        })?;
    }
    Ok(())
}

fn register_ssh_ingress_from_local(
    node: &mut VosNode,
    local: &local_config::LocalConfig,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let mut names = BTreeSet::new();
    for listener in &local.ingress.ssh {
        validate_ingress_name("SSH", &listener.name)?;
        if !names.insert(listener.name.as_str()) {
            anyhow::bail!("duplicate SSH ingress name '{}'", listener.name);
        }
        let listen = listener
            .listen
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid SSH ingress address: {error}"))?;
        node.add_ssh_ingress(vos::ssh_ingress::SshIngressConfig {
            name: listener.name.clone(),
            listen,
            host_key: data_dir
                .join("private/ssh")
                .join(&listener.name)
                .join("host_ed25519"),
            max_connections: listener.max_connections,
            max_sessions_per_member: listener.max_sessions_per_member,
        })?;
    }
    Ok(())
}

fn validate_ingress_name(kind: &str, name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!(
            "{kind} ingress name '{name}' must contain only ASCII letters, digits, '-' or '_'"
        );
    }
    Ok(())
}

fn publish_endpoint(
    node: &VosNode,
    data_dir: &Path,
    prefix: u16,
    extensions: Vec<super::endpoint::ExtensionCaps>,
) -> anyhow::Result<()> {
    let network = node
        .network()
        .ok_or_else(|| anyhow::anyhow!("network was not attached"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let addresses = loop {
        let addresses = network.listen_addrs();
        if !addresses.is_empty() {
            break addresses;
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("swarm did not bind a listen address within three seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    super::endpoint::write(
        data_dir,
        &super::endpoint::Endpoint {
            peer_id: network.peer_id().to_string(),
            multiaddrs: addresses.iter().map(ToString::to_string).collect(),
            prefix,
            pid: std::process::id(),
            extensions,
        },
    )
}

fn cleanup_endpoint_after_collect<T, E>(data_dir: &Path, result: Result<T, E>) -> Result<T, E> {
    super::endpoint::delete(data_dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_handshake_failure_is_not_downgraded() {
        let error =
            require_boot_registry_handshake(Err(vos::actors::client::ClientError::Unreachable))
                .expect_err("handshake failure must stop boot");
        assert!(error.to_string().contains("protocol handshake failed"));
    }

    #[test]
    fn ingress_names_are_bounded_to_portable_ascii() {
        for valid in ["api", "ssh-01", "operator_shell"] {
            validate_ingress_name("test", valid).unwrap();
        }
        for invalid in ["", "../api", "with space", "ümlaut"] {
            assert!(validate_ingress_name("test", invalid).is_err());
        }
    }
}
