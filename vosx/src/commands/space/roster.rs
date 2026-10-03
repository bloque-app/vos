//! `space join`, `space enroll-node`, `space prepare-roster` and
//! `space use-roster` — bring an existing Space onto more machines.
//!
//! The fixed roster is the only multi-node system-Agent placement: the Space
//! root certifies one common bootstrap bundle over exactly three signed node
//! enrollments, and every member starts once from that bundle. Each machine
//! runs the Space root operator identity with its own node key. Adding a node
//! after genesis is a Shared membership change, not a new roster.

use std::path::{Path, PathBuf};

use crate::commands::space::{clean_startup, local_config};
use crate::spaces_index;

/// File name, under the Space data directory, of the adopted roster bundle.
const ROSTER_BUNDLE_FILE: &str = "system-roster.bundle";
/// File name, under the Space data directory, of this node's enrollment.
const NODE_ENROLLMENT_FILE: &str = "node-enrollment.vne";

/// Lay out a Space this machine did not create: data directory, a fresh
/// owner-only node key and the index entry with its bootnodes. The registry
/// genesis is not minted here; `space up` syncs and verifies it from peers.
pub fn join(
    space: &str,
    name: &str,
    bootnodes: &[String],
    data_dir: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    let space_id = parse_space_id(space)?;
    for bootnode in bootnodes {
        bootnode
            .parse::<libp2p::Multiaddr>()
            .map_err(|error| anyhow::anyhow!("invalid bootnode multiaddr '{bootnode}': {error}"))?;
    }
    let (registry_hash, _, _) = crate::commands::space::new::resolve_registry_source(None)?;
    let data_dir = data_dir.unwrap_or_else(|| crate::paths::space_dir(&space_id));
    let data_dir = spaces_index::normalize_data_directory(&data_dir)?;
    let mut index = spaces_index::LockedSpacesIndex::acquire()?;
    if let Some(existing) = index
        .spaces
        .iter()
        .find(|entry| entry.id == hex::encode(space_id))
    {
        anyhow::bail!(
            "space {} is already known locally as '{}' at {}",
            existing.id,
            existing.name,
            existing.data_dir
        );
    }
    let mut entry = spaces_index::entry_for_at(&space_id, name, &data_dir)?;
    entry.registry_hash = registry_hash.to_hex();
    entry.bootnodes = bootnodes.to_vec();
    index.validate_upsert(&entry)?;
    anyhow::ensure!(
        !data_dir.exists(),
        "space data dir already exists: {}",
        data_dir.display()
    );
    let staging = data_dir.with_extension(format!("joining-{}", std::process::id()));
    std::fs::create_dir_all(staging.join("agents"))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
    }
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let key_bytes = keypair
        .to_protobuf_encoding()
        .map_err(|error| anyhow::anyhow!("encode node key: {error}"))?;
    crate::secure_file::write_owner_only_atomic(&staging.join("node.key"), &key_bytes)?;
    local_config::save(&staging, &local_config::LocalConfig::for_new_space())?;
    std::fs::rename(&staging, &data_dir)?;
    spaces_index::upsert(&mut index, entry);
    index.save()?;
    Ok(data_dir)
}

/// Write this node's signed enrollment for the Space root to certify.
pub fn enroll_node(space: &str, out: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let (entry, data_dir) = known_space(space)?;
    let space_id = entry_space_id(&entry)?;
    let operator = crate::identity::load_existing()?;
    let daemon = super::up::load_daemon_keypair(&data_dir)?;
    let enrollment = clean_startup::local_node_enrollment(space_id, &operator, &daemon)?;
    let out = out.unwrap_or_else(|| data_dir.join(NODE_ENROLLMENT_FILE));
    crate::secure_file::write_owner_only_atomic(
        &out,
        &clean_startup::encode_node_enrollment(&enrollment),
    )?;
    println!("node {}", hex::encode(enrollment.node.0));
    Ok(out)
}

/// On the Space root: certify a common three-node bootstrap bundle.
pub fn prepare_roster(space: &str, enrollments: &[PathBuf], out: &Path) -> anyhow::Result<()> {
    let (entry, data_dir) = known_space(space)?;
    let space_id = entry_space_id(&entry)?;
    let operator = crate::identity::load_existing()?;
    let daemon = super::up::load_daemon_keypair(&data_dir)?;
    let local = local_config::load(&data_dir)?;
    let enrollments = enrollments
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path)?;
            clean_startup::decode_node_enrollment(&bytes)
                .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let bundle = clean_startup::prepare_fixed_roster_bundle(
        &data_dir,
        space_id,
        &operator,
        &daemon,
        local.local_agent_storage,
        &enrollments,
        #[cfg(test)]
        None,
    )?;
    crate::secure_file::write_owner_only_atomic(out, &bundle)?;
    Ok(())
}

/// Adopt a certified roster bundle for this node's first system-Agent start.
pub fn use_roster(space: &str, bundle: &Path) -> anyhow::Result<()> {
    let (_, data_dir) = known_space(space)?;
    anyhow::ensure!(
        !data_dir.join("system-agent").exists(),
        "this node already started a system Agent; a roster applies only to a first start"
    );
    let bytes = std::fs::read(bundle)?;
    crate::secure_file::write_owner_only_atomic(&data_dir.join(ROSTER_BUNDLE_FILE), &bytes)?;
    let mut config = local_config::load(&data_dir)?;
    config.system_bootstrap_bundle = Some(PathBuf::from(ROSTER_BUNDLE_FILE));
    local_config::save(&data_dir, &config)?;
    Ok(())
}

fn known_space(query: &str) -> anyhow::Result<(spaces_index::SpaceEntry, PathBuf)> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, query)?.clone();
    let data_dir = PathBuf::from(&entry.data_dir);
    Ok((entry, data_dir))
}

fn entry_space_id(entry: &spaces_index::SpaceEntry) -> anyhow::Result<[u8; 32]> {
    entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in the local index is not canonical"))
}

fn parse_space_id(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|_| anyhow::anyhow!("space id must be 64 hexadecimal characters"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("space id must be 64 hexadecimal characters"))
}
