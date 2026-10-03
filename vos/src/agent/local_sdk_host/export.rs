//! Same-identity cold-standby export/import for one clean Local Agent.
//!
//! A Local Agent has exactly one replica and its descriptor binds that replica
//! to one transport `NodeId`, so the only honest re-hosting is the SAME node
//! identity (the same node key) on another machine or data directory: a cold
//! standby / disaster-recovery move. This bundle therefore carries no new
//! authority and changes no membership. It is an opaque copy of one exact
//! committed slot (the AGI3 image bytes plus its content-addressed catalog)
//! bound to the root's `(space, node)` and the Agent identity.
//!
//! The whole-bundle digest detects accidental damage only; it is not a
//! signature. Import re-admits everything the way a reopen of the source root
//! would (descriptor/scope binding, signed runtime package, catalog closure,
//! guest management-history recovery check), entirely in memory before the
//! destination root is touched. Anyone able to forge a bundle that passes
//! those checks could equally write the source data directory, so a bundle
//! must be stored and transported with the same care as that directory.
//!
//! Not covered here: a full-Space cold standby also needs the Shared system
//! Agent's portable backup, and the node's Authority route projection still
//! has to agree with the imported Local images (the projection audit is
//! unchanged and fails closed on mismatch).

use alloc::vec::Vec;
use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use crate::agent_sdk::{AgentDescriptor, AgentId, NodeId, SpaceId};
use crate::service::wire::ServiceWire as _;
use crate::service::{BlobRef, DeploymentId, ProgramId};

use super::super::driver::{
    AgentDriver, AgentImage, AgentImageStore as _, AgentStoreError, AgentTrustProvider,
    MAX_AGENT_IMAGE_BYTES, MemoryAgentStore,
};
use super::{
    CATALOG_DIRECTORY, CATALOG_KINDS, IMAGE_FILE, LocalAgentHost, LocalAgentHostError,
    MAX_LOCAL_HOST_AGENTS, RootScope, create_agent_slot, decode_agent_id, encode_agent_id,
    image_path, open_read_nofollow, path_exists, remove_unpublished_slot, require_private_file,
    sync_directory, validate_agent_slot, validate_descriptor_for_scope, validate_same_directory,
    write_new_private_file,
};

const EXPORT_MAGIC: &[u8; 4] = b"LAX1";
const EXPORT_VERSION: u16 = 1;
const EXPORT_DIGEST_DOMAIN: &[u8] = b"vos/local-agent-host/export/v1";
const EXPORT_LEAF_DOMAIN: &[u8] = b"vos/local-agent-host/export-leaf/v1";
/// Complete image written beside the staged catalog. It is renamed to
/// `image` only after every leaf is durable, so a crash before that rename
/// leaves a stage that create-recovery retires as empty.
const IMPORT_IMAGE_STAGE_FILE: &str = "image.import";
const CATALOG_SUFFIXES: [&str; 5] = ["vos", "pvm", "agent", "roles", "args"];
const EXPORT_HEADER_BYTES: usize = 4 + 2 + 32 + 32 + 32 + 4;
const EXPORT_LEAF_OVERHEAD: usize = 1 + 32 + 4 + 32;
/// Runtime package plus package/program/schema/policy/constructor data for
/// every actor of a Standard runtime.
const MAX_LOCAL_AGENT_EXPORT_LEAVES: usize = super::super::MAX_CATALOG_ARTIFACT_REFERENCES as usize
    + 1
    + super::super::contract::STANDARD_MAX_ACTORS as usize;
/// Absolute ceiling for one bundle: the bounded image plus the catalog
/// closure, whose referenced bytes are protocol-bounded and whose programs are
/// carried inside those packages.
const MAX_LOCAL_AGENT_EXPORT_BYTES: usize = EXPORT_HEADER_BYTES
    + MAX_AGENT_IMAGE_BYTES
    + 4
    + 2 * super::super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES as usize
    + MAX_LOCAL_AGENT_EXPORT_LEAVES * EXPORT_LEAF_OVERHEAD
    + 32;

const fn leaf_limit(kind: u8) -> usize {
    const PACKAGE: usize = if super::super::package::MAX_ENCODED_PACKAGE_BYTES
        > crate::agent_sdk::package::MAX_PACKAGE_ENCODED_BYTES
    {
        super::super::package::MAX_ENCODED_PACKAGE_BYTES
    } else {
        crate::agent_sdk::package::MAX_PACKAGE_ENCODED_BYTES
    };
    match kind {
        0 => PACKAGE,
        1 => super::super::execution::MAX_EXECUTION_PROGRAM_BYTES,
        2 => super::super::schema::MAX_ENCODED_BYTES,
        3 => super::super::execution::MAX_EXECUTION_POLICY_BYTES,
        4 => super::super::MAX_INSTALLATION_DATA_BYTES,
        _ => 0,
    }
}

struct ExportLeaf<'a> {
    kind: u8,
    id: [u8; 32],
    bytes: &'a [u8],
}

struct LocalAgentExport<'a> {
    scope: RootScope,
    agent: AgentId,
    image: &'a [u8],
    leaves: Vec<ExportLeaf<'a>>,
}

fn leaf_hash(kind: u8, id: &[u8; 32], bytes: &[u8]) -> crate::agent_sdk::Hash {
    crate::agent_sdk::Hash::digest(EXPORT_LEAF_DOMAIN, &[&[kind], id, bytes])
}

fn export_digest(body: &[u8]) -> crate::agent_sdk::Hash {
    crate::agent_sdk::Hash::digest(EXPORT_DIGEST_DOMAIN, &[body])
}

fn push_len(output: &mut Vec<u8>, len: usize) -> Result<(), LocalAgentHostError> {
    let len = u32::try_from(len).map_err(|_| LocalAgentHostError::LimitExceeded)?;
    output.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn encode_export(export: &LocalAgentExport<'_>) -> Result<Vec<u8>, LocalAgentHostError> {
    if export.image.len() > MAX_AGENT_IMAGE_BYTES
        || export.leaves.len() > MAX_LOCAL_AGENT_EXPORT_LEAVES
    {
        return Err(LocalAgentHostError::LimitExceeded);
    }
    let mut output = Vec::new();
    output.extend_from_slice(EXPORT_MAGIC);
    output.extend_from_slice(&EXPORT_VERSION.to_le_bytes());
    output.extend_from_slice(export.scope.space.as_bytes());
    output.extend_from_slice(export.scope.node.as_bytes());
    output.extend_from_slice(export.agent.as_bytes());
    push_len(&mut output, export.image.len())?;
    output.extend_from_slice(export.image);
    push_len(&mut output, export.leaves.len())?;
    for leaf in &export.leaves {
        if leaf.bytes.len() > leaf_limit(leaf.kind) {
            return Err(LocalAgentHostError::LimitExceeded);
        }
        output.push(leaf.kind);
        output.extend_from_slice(&leaf.id);
        push_len(&mut output, leaf.bytes.len())?;
        output.extend_from_slice(leaf.bytes);
        output.extend_from_slice(leaf_hash(leaf.kind, &leaf.id, leaf.bytes).as_bytes());
        if output.len() > MAX_LOCAL_AGENT_EXPORT_BYTES - 32 {
            return Err(LocalAgentHostError::LimitExceeded);
        }
    }
    let digest = export_digest(&output);
    output.extend_from_slice(digest.as_bytes());
    Ok(output)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], LocalAgentHostError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(LocalAgentHostError::Corrupt)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn fixed(&mut self) -> Result<[u8; 32], LocalAgentHostError> {
        self.take(32)?
            .try_into()
            .map_err(|_| LocalAgentHostError::Corrupt)
    }

    fn len(&mut self, max: usize) -> Result<usize, LocalAgentHostError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| LocalAgentHostError::Corrupt)?;
        let len = u32::from_le_bytes(bytes) as usize;
        if len > max {
            return Err(LocalAgentHostError::LimitExceeded);
        }
        Ok(len)
    }
}

/// Strict canonical decode. The digest is checked before any field is
/// interpreted; every length is bounded before it is used.
fn decode_export(bytes: &[u8]) -> Result<LocalAgentExport<'_>, LocalAgentHostError> {
    if bytes.len() > MAX_LOCAL_AGENT_EXPORT_BYTES {
        return Err(LocalAgentHostError::LimitExceeded);
    }
    if bytes.len() < EXPORT_HEADER_BYTES + 4 + 32 {
        return Err(LocalAgentHostError::Corrupt);
    }
    let (body, digest) = bytes.split_at(bytes.len() - 32);
    if export_digest(body).as_bytes() != digest {
        return Err(LocalAgentHostError::Corrupt);
    }
    let mut cursor = Cursor {
        bytes: body,
        offset: 0,
    };
    if cursor.take(4)? != EXPORT_MAGIC || cursor.take(2)? != EXPORT_VERSION.to_le_bytes().as_slice()
    {
        return Err(LocalAgentHostError::Corrupt);
    }
    let scope = RootScope {
        space: SpaceId(cursor.fixed()?),
        node: NodeId(cursor.fixed()?),
    };
    let agent = AgentId(cursor.fixed()?);
    if scope.space == SpaceId::ZERO || scope.node == NodeId::ZERO || agent == AgentId::ZERO {
        return Err(LocalAgentHostError::Corrupt);
    }
    let image_len = cursor.len(MAX_AGENT_IMAGE_BYTES)?;
    let image = cursor.take(image_len)?;
    let count = cursor.len(MAX_LOCAL_AGENT_EXPORT_LEAVES)?;
    let mut leaves: Vec<ExportLeaf<'_>> = Vec::new();
    for _ in 0..count {
        let kind = cursor.take(1)?[0];
        if usize::from(kind) >= CATALOG_KINDS.len() {
            return Err(LocalAgentHostError::Corrupt);
        }
        let id = cursor.fixed()?;
        let len = cursor.len(leaf_limit(kind))?;
        let leaf_bytes = cursor.take(len)?;
        if cursor.take(32)? != leaf_hash(kind, &id, leaf_bytes).as_bytes()
            || id == [0; 32]
            || leaves
                .last()
                .is_some_and(|previous| (previous.kind, previous.id) >= (kind, id))
        {
            return Err(LocalAgentHostError::Corrupt);
        }
        leaves.push(ExportLeaf {
            kind,
            id,
            bytes: leaf_bytes,
        });
    }
    if cursor.offset != body.len() {
        return Err(LocalAgentHostError::Corrupt);
    }
    Ok(LocalAgentExport {
        scope,
        agent,
        image,
        leaves,
    })
}

fn store_error(_: AgentStoreError) -> LocalAgentHostError {
    LocalAgentHostError::Corrupt
}

/// Re-admit the complete slot in memory exactly as a reopen would, without
/// touching any root. The catalog must be exactly the authenticated closure:
/// a leaf that reopen would prune makes the bundle non-canonical.
fn admit_export(
    export: &LocalAgentExport<'_>,
    scope: RootScope,
    trust: Arc<dyn AgentTrustProvider>,
) -> Result<AgentDescriptor, LocalAgentHostError> {
    if export.scope != scope {
        return Err(LocalAgentHostError::InvalidScope);
    }
    let image = AgentImage::decode(export.image).map_err(|_| LocalAgentHostError::Corrupt)?;
    if image.encode() != export.image {
        return Err(LocalAgentHostError::Corrupt);
    }
    let descriptor = image
        .clean_descriptor
        .clone()
        .ok_or(LocalAgentHostError::Corrupt)?;
    validate_descriptor_for_scope(scope, &descriptor)?;
    if descriptor.identity.agent != export.agent {
        return Err(LocalAgentHostError::Alias);
    }
    let mut store = MemoryAgentStore::default();
    store.commit(None, &image).map_err(store_error)?;
    for leaf in &export.leaves {
        let reference = BlobRef::of_bytes(leaf.bytes);
        let stored = match leaf.kind {
            0 if reference.hash.0 == leaf.id => store.put_package(&reference, leaf.bytes),
            1 => store.put_program(ProgramId(leaf.id), leaf.bytes),
            2 => store.put_actor_schema(DeploymentId(leaf.id), &reference, leaf.bytes),
            3 => store.put_actor_policies(DeploymentId(leaf.id), &reference, leaf.bytes),
            4 if reference.hash.0 == leaf.id => store.put_installation_data(&reference, leaf.bytes),
            _ => Err(AgentStoreError::Corrupt),
        };
        if !stored.map_err(store_error)? {
            return Err(LocalAgentHostError::Corrupt);
        }
    }
    let driver = AgentDriver::open_sdk(store, trust)?;
    if driver.image() != &image {
        return Err(LocalAgentHostError::Corrupt);
    }
    let store = driver.into_store();
    for leaf in &export.leaves {
        let reference = BlobRef::of_bytes(leaf.bytes);
        let retained = match leaf.kind {
            0 => store.load_package(&reference).map(|bytes| bytes.is_some()),
            1 => store
                .load_program(ProgramId(leaf.id))
                .map(|bytes| bytes.is_some()),
            2 => store
                .load_actor_schema(DeploymentId(leaf.id))
                .map(|blob| blob.is_some_and(|blob| blob.reference == reference)),
            3 => store
                .load_actor_policies(DeploymentId(leaf.id))
                .map(|blob| blob.is_some_and(|blob| blob.reference == reference)),
            4 => store
                .load_installation_data(&reference)
                .map(|blob| blob.is_some()),
            _ => Ok(false),
        }
        .map_err(store_error)?;
        if !retained {
            return Err(LocalAgentHostError::Corrupt);
        }
    }
    Ok(descriptor)
}

fn read_private_bounded(path: &Path, max: usize) -> Result<Vec<u8>, LocalAgentHostError> {
    require_private_file(path)?;
    let file = open_read_nofollow(path)?;
    let length = file.metadata().map_err(|_| LocalAgentHostError::Io)?.len();
    if length > max as u64 {
        return Err(LocalAgentHostError::LimitExceeded);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LocalAgentHostError::Io)?;
    if bytes.len() != length as usize {
        return Err(LocalAgentHostError::Corrupt);
    }
    Ok(bytes)
}

/// Read the slot's catalog leaves in canonical `(kind, id)` order. Staged
/// `.next` leaves mean an unfinished or unreconciled write: refuse.
fn read_catalog_leaves(slot: &Path) -> Result<Vec<(u8, [u8; 32], Vec<u8>)>, LocalAgentHostError> {
    let catalog = slot.join(CATALOG_DIRECTORY);
    let mut leaves = Vec::new();
    for (kind, name) in CATALOG_KINDS.iter().enumerate() {
        let directory = catalog.join(name);
        let mut found = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|_| LocalAgentHostError::Io)? {
            let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| LocalAgentHostError::InvalidRoot)?;
            let (identity, suffix) = file_name
                .split_once('.')
                .ok_or(LocalAgentHostError::InvalidRoot)?;
            if suffix != CATALOG_SUFFIXES[kind] {
                return Err(LocalAgentHostError::Busy);
            }
            // Catalog leaves use the same lowercase 32-byte hex as slots.
            let id = decode_agent_id(identity).ok_or(LocalAgentHostError::InvalidRoot)?;
            if leaves.len() + found.len() >= MAX_LOCAL_AGENT_EXPORT_LEAVES {
                return Err(LocalAgentHostError::LimitExceeded);
            }
            found.push(id.0);
        }
        found.sort_unstable();
        for id in found {
            let path = directory.join(format!(
                "{}.{}",
                encode_agent_id(AgentId(id)),
                CATALOG_SUFFIXES[kind]
            ));
            leaves.push((
                kind as u8,
                id,
                read_private_bounded(&path, leaf_limit(kind as u8))?,
            ));
        }
    }
    Ok(leaves)
}

impl LocalAgentHost {
    /// Export one idle Local Agent as an opaque same-identity bundle for a
    /// cold standby root bound to this exact `(space, node)`. The bundle is
    /// re-admitted in memory before it is returned, so an export that cannot
    /// be imported is refused here instead.
    pub fn export_agent(&self, agent: AgentId) -> Result<Vec<u8>, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        validate_descriptor_for_scope(self.scope, &hosted.descriptor)?;
        if hosted.descriptor.identity.agent != agent {
            return Err(LocalAgentHostError::Alias);
        }
        let slot = self.agent_path(agent);
        validate_same_directory(&hosted.directory, &slot)?;
        validate_agent_slot(&slot, false)?;
        let image = read_private_bounded(&image_path(&slot), MAX_AGENT_IMAGE_BYTES)?;
        let decoded = AgentImage::decode(&image).map_err(|_| LocalAgentHostError::Corrupt)?;
        if &decoded != hosted.driver.image()
            || decoded.clean_descriptor.as_ref() != Some(&hosted.descriptor)
        {
            return Err(LocalAgentHostError::Corrupt);
        }
        let leaves = read_catalog_leaves(&slot)?;
        let bytes = encode_export(&LocalAgentExport {
            scope: self.scope,
            agent,
            image: &image,
            leaves: leaves
                .iter()
                .map(|(kind, id, bytes)| ExportLeaf {
                    kind: *kind,
                    id: *id,
                    bytes,
                })
                .collect(),
        })?;
        admit_export(&decode_export(&bytes)?, self.scope, self.trust.clone())?;
        Ok(bytes)
    }

    /// Import a bundle produced by [`Self::export_agent`] into this root,
    /// which must be bound to the same `(space, node)`. Every refusal happens
    /// before any filesystem mutation. An identical re-import is a no-op; an
    /// occupied slot with different content is `AlreadyExists`. The slot is
    /// staged under `.creating` and published exactly like `create_agent`, so
    /// restart recovery promotes a complete stage or retires an empty one.
    pub fn import_agent(&mut self, bytes: &[u8]) -> Result<AgentId, LocalAgentHostError> {
        self.verify_root_scope()?;
        let export = decode_export(bytes)?;
        if export.scope != self.scope {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let agent = export.agent;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if self.agents.contains_key(&agent) {
            return if self.export_agent(agent)? == bytes {
                Ok(agent)
            } else {
                Err(LocalAgentHostError::AlreadyExists)
            };
        }
        admit_export(&export, self.scope, self.trust.clone())?;
        if self.agents.len() + self.executing.len() >= MAX_LOCAL_HOST_AGENTS {
            return Err(LocalAgentHostError::LimitExceeded);
        }
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if path_exists(&stage)? || path_exists(&destination)? {
            return Err(LocalAgentHostError::AlreadyExists);
        }
        create_agent_slot(&stage)?;
        let staged = write_stage(&stage, &export).and_then(|()| {
            Self::open_hosted_at(self.scope, self.trust.clone(), agent, &stage).map(drop)
        });
        if let Err(error) = staged {
            remove_unpublished_slot(&stage)?;
            return Err(error);
        }
        validate_agent_slot(&stage, true)?;
        sync_directory(&stage)?;
        fs::rename(&stage, &destination).map_err(|_| LocalAgentHostError::Io)?;
        let publication = self
            .root_directory
            .sync_all()
            .map_err(|_| LocalAgentHostError::Io)
            .and_then(|()| sync_directory(&self.root.join(super::CREATING_DIRECTORY)));
        let hosted = self.open_hosted(agent, &destination)?;
        if self.agents.insert(agent, hosted).is_some() {
            return Err(LocalAgentHostError::Alias);
        }
        publication.map(|()| agent)
    }
}

/// Write every catalog leaf durably, then publish the image by one rename.
fn write_stage(stage: &Path, export: &LocalAgentExport<'_>) -> Result<(), LocalAgentHostError> {
    let catalog = stage.join(CATALOG_DIRECTORY);
    for leaf in &export.leaves {
        let kind = usize::from(leaf.kind);
        let path = catalog.join(CATALOG_KINDS[kind]).join(format!(
            "{}.{}",
            encode_agent_id(AgentId(leaf.id)),
            CATALOG_SUFFIXES[kind]
        ));
        write_new_private_file(&path, leaf.bytes)?;
    }
    for kind in CATALOG_KINDS {
        sync_directory(&catalog.join(kind))?;
    }
    sync_directory(&catalog)?;
    let image_stage = stage.join(IMPORT_IMAGE_STAGE_FILE);
    write_new_private_file(&image_stage, export.image)?;
    sync_directory(stage)?;
    fs::rename(&image_stage, stage.join(IMAGE_FILE)).map_err(|_| LocalAgentHostError::Io)?;
    sync_directory(stage)
}

#[cfg(test)]
pub(super) fn reseal_for_test(bytes: &mut [u8]) {
    let body = bytes.len() - 32;
    let digest = export_digest(&bytes[..body]);
    bytes[body..].copy_from_slice(digest.as_bytes());
}
