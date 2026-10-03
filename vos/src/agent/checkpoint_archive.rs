//! Off-node archive of certified Shared Agent checkpoints and log segments.
//!
//! This is storage, not authority. A record read back proves only that the
//! store returned bytes which were once published under the same canonical
//! key; its digest is unkeyed integrity, not authentication. A checkpoint
//! certificate must still be promoted with [`verify_archived_checkpoint`]
//! against an independently admitted committee, and the bundle must still
//! pass the host's own restore validation before anything is installed.
//! Segment bytes are opaque here; their per-entry commit certificates are
//! verified by whoever replays them.
//!
//! Uploading is best-effort maintenance. Callers must never gate a commit,
//! an acknowledgement or a mandatory checkpoint on a sink call.

use alloc::string::String;
use alloc::vec::Vec;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::genesis::{AgentGenesisAdmissionId, AgentReplicaCommittee};
use super::journal::AgentJournalGenesisId;
use super::shared_commit::{
    MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
    MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES, OrderedCommitClaim,
    SharedAgentCommonSnapshotCertificate, SharedAgentSnapshotCertificate,
    VerifiedSharedAgentCommonSnapshot, VerifiedSharedAgentSnapshot,
};
use super::shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES;
use crate::service::{AgentId, Hash, ServiceWire, SpaceId};

const RECORD_MAGIC: &[u8; 4] = b"VCA1";
const RECORD_DOMAIN: &[u8] = b"vos/agent/checkpoint-archive/record/v1";
const GENERATION_DOMAIN: &[u8] = b"vos/agent/checkpoint-archive/generation/v1";
const CHECKPOINT_TAG: u8 = 0;
const SEGMENT_TAG: u8 = 1;
const RECORD_SUFFIX: &str = ".vca";
/// Names with this prefix are unpublished scratch files. A crash may leave
/// them behind; readers ignore them and they never shadow a record.
const TEMP_PREFIX: &str = ".tmp-";
const SCOPE_BYTES: usize = 4 * 32;
const DIGEST_BYTES: usize = 32;

const fn max_usize(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Largest certificate either supported checkpoint kind can encode.
pub const MAX_ARCHIVED_CERTIFICATE_BYTES: usize = max_usize(
    MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
    MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES,
);
/// Hard ceiling for one whole-buffer checkpoint bundle. It covers the
/// current portable/common bundle ceilings; streamed AXJ1 closures need a
/// streaming variant rather than a larger buffer.
pub const MAX_ARCHIVED_CHECKPOINT_BYTES: usize = 384 * 1024 * 1024;
/// Hard ceiling for one opaque log segment.
pub const MAX_ARCHIVED_SEGMENT_BYTES: usize = 64 * 1024 * 1024;
/// A segment never spans more than the ordered-evidence window.
pub const MAX_ARCHIVED_SEGMENT_ENTRIES: u64 = MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64;
/// Hard ceiling on directory entries scanned for one scope.
pub const MAX_ARCHIVE_LISTING: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointArchiveError {
    /// The key itself is non-canonical or out of range.
    InvalidKey,
    /// A configured or hard bound refused the request before allocation.
    LimitExceeded,
    /// Different bytes (or an overlapping segment) already own the key.
    Conflict,
    /// Stored bytes, names or file types are not exactly what was published.
    Corrupt,
    /// The certificate does not decode canonically, does not match its key,
    /// or does not verify against the trusted committee.
    CertificateInvalid,
    /// Backend I/O failed; nothing about the record is implied.
    Unavailable,
}

/// One Agent generation, matching the Raft generation route key: committee
/// epochs may change inside it without changing the archive namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveScope {
    pub space: SpaceId,
    pub agent: AgentId,
    pub genesis: AgentJournalGenesisId,
    pub admission: AgentGenesisAdmissionId,
}

impl ArchiveScope {
    fn validate(&self) -> Result<(), CheckpointArchiveError> {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
        {
            return Err(CheckpointArchiveError::InvalidKey);
        }
        Ok(())
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.space.0);
        output.extend_from_slice(&self.agent.0);
        output.extend_from_slice(&self.genesis.0);
        output.extend_from_slice(self.admission.as_bytes());
    }

    fn generation(&self) -> Hash {
        Hash::digest(
            GENERATION_DOMAIN,
            &[&self.genesis.0, self.admission.as_bytes()],
        )
    }

    fn matches(&self, ordered: &OrderedCommitClaim) -> bool {
        ordered.space() == self.space
            && ordered.agent() == self.agent
            && ordered.genesis() == self.genesis
            && ordered.admission() == self.admission
    }
}

/// Which certificate authenticates an archived checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArchivedCertificateKind {
    /// AGQ4 fixed-three common-state quorum certificate.
    Common = 0,
    /// AGS single-voter physical checkpoint certificate. It is node/store
    /// bound and is not by itself installable on another node.
    Singleton = 1,
}

impl ArchivedCertificateKind {
    const fn name(self) -> char {
        match self {
            Self::Common => 'q',
            Self::Singleton => 's',
        }
    }

    fn from_name(name: u8) -> Option<Self> {
        match name {
            b'q' => Some(Self::Common),
            b's' => Some(Self::Singleton),
            _ => None,
        }
    }
}

/// `position` is the certified Raft index; `certificate` is the exact
/// certificate commitment, so the key content-addresses the certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchivedCheckpointKey {
    pub scope: ArchiveScope,
    pub kind: ArchivedCertificateKind,
    pub position: u64,
    pub certificate: Hash,
}

impl ArchivedCheckpointKey {
    fn validate(&self) -> Result<(), CheckpointArchiveError> {
        self.scope.validate()?;
        if self.position == 0 || self.certificate == Hash::ZERO {
            return Err(CheckpointArchiveError::InvalidKey);
        }
        Ok(())
    }

    fn file_name(&self) -> String {
        format!(
            "c{}-{:016x}-{}{RECORD_SUFFIX}",
            self.kind.name(),
            self.position,
            hex32(&self.certificate.0)
        )
    }

    fn prefix(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(4 + 1 + SCOPE_BYTES + 1 + 8 + 32);
        output.extend_from_slice(RECORD_MAGIC);
        output.push(CHECKPOINT_TAG);
        self.scope.encode(&mut output);
        output.push(self.kind as u8);
        output.extend_from_slice(&self.position.to_le_bytes());
        output.extend_from_slice(&self.certificate.0);
        output
    }
}

/// Inclusive Raft index range `first..=last` of one opaque segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchivedSegmentKey {
    pub scope: ArchiveScope,
    pub first: u64,
    pub last: u64,
}

impl ArchivedSegmentKey {
    fn validate(&self) -> Result<(), CheckpointArchiveError> {
        self.scope.validate()?;
        if self.first == 0
            || self.last < self.first
            || self.last - self.first >= MAX_ARCHIVED_SEGMENT_ENTRIES
        {
            return Err(CheckpointArchiveError::InvalidKey);
        }
        Ok(())
    }

    fn file_name(&self) -> String {
        format!("s-{:016x}-{:016x}{RECORD_SUFFIX}", self.first, self.last)
    }

    fn prefix(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(4 + 1 + SCOPE_BYTES + 16);
        output.extend_from_slice(RECORD_MAGIC);
        output.push(SEGMENT_TAG);
        self.scope.encode(&mut output);
        output.extend_from_slice(&self.first.to_le_bytes());
        output.extend_from_slice(&self.last.to_le_bytes());
        output
    }

    const fn overlaps(&self, other: &Self) -> bool {
        self.first <= other.last && other.first <= self.last
    }
}

/// Untrusted archived checkpoint material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedCheckpoint {
    pub certificate: Vec<u8>,
    pub bundle: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveReceipt {
    /// Record digest over the canonical key, certificate and payload.
    pub digest: Hash,
    /// False when identical bytes were already published (exact retry).
    pub created: bool,
}

/// Publication side. Implementations publish atomically, never replace
/// different bytes under one key, accept identical retries, and return
/// success only after the record is durable in the backend. An error may
/// follow a durable write; an exact retry then succeeds with `created: false`.
/// One writer per scope is assumed; overlap refusal is not a cross-writer lock.
pub trait CheckpointArchiveSink: Send + Sync {
    fn put_checkpoint(
        &self,
        key: &ArchivedCheckpointKey,
        certificate: &[u8],
        bundle: &[u8],
    ) -> Result<ArchiveReceipt, CheckpointArchiveError>;

    fn put_segment(
        &self,
        key: &ArchivedSegmentKey,
        entries: &[u8],
    ) -> Result<ArchiveReceipt, CheckpointArchiveError>;
}

/// Retrieval side. Reads enforce size bounds before allocating and return
/// only records whose bytes and embedded key match the request exactly.
pub trait CheckpointArchiveSource: Send + Sync {
    fn get_checkpoint(
        &self,
        key: &ArchivedCheckpointKey,
    ) -> Result<Option<ArchivedCheckpoint>, CheckpointArchiveError>;

    /// Highest archived position; ties are broken by the lowest
    /// `(kind, certificate)`. Selection is not verification.
    fn latest_checkpoint(
        &self,
        scope: &ArchiveScope,
    ) -> Result<Option<ArchivedCheckpointKey>, CheckpointArchiveError>;

    /// Segments containing any index after `position`, ordered by `first`,
    /// at most `maximum`. Page by passing the last returned `last`.
    fn list_segments_after(
        &self,
        scope: &ArchiveScope,
        position: u64,
        maximum: usize,
    ) -> Result<Vec<ArchivedSegmentKey>, CheckpointArchiveError>;

    fn get_segment(
        &self,
        key: &ArchivedSegmentKey,
    ) -> Result<Option<Vec<u8>>, CheckpointArchiveError>;
}

/// Highest index `end` such that every index in `after+1..=end` is covered by
/// the ordered, non-overlapping `segments`. Anything later is behind a gap
/// and is not recoverable from this archive.
pub fn contiguous_archived_end(after: u64, segments: &[ArchivedSegmentKey]) -> u64 {
    let mut end = after;
    for segment in segments {
        if segment.last <= end {
            continue;
        }
        if segment.first > end.saturating_add(1) {
            break;
        }
        end = segment.last;
    }
    end
}

enum BoundCertificate {
    Common(SharedAgentCommonSnapshotCertificate),
    Singleton(SharedAgentSnapshotCertificate),
}

/// Structural binding only: canonical bytes, exact commitment, scope and
/// position. This grants no trust; see [`verify_archived_checkpoint`].
fn bind_certificate(
    key: &ArchivedCheckpointKey,
    certificate: &[u8],
) -> Result<BoundCertificate, CheckpointArchiveError> {
    if certificate.len() > MAX_ARCHIVED_CERTIFICATE_BYTES {
        return Err(CheckpointArchiveError::LimitExceeded);
    }
    let invalid = |_| CheckpointArchiveError::CertificateInvalid;
    let (bound, encoded, commitment, ordered, position) = match key.kind {
        ArchivedCertificateKind::Common => {
            let decoded =
                SharedAgentCommonSnapshotCertificate::decode(certificate).map_err(invalid)?;
            let encoded = decoded.encode();
            let commitment = decoded.commitment();
            let ordered = decoded.claim().ordered().clone();
            let position = ordered.raft_index();
            (
                BoundCertificate::Common(decoded),
                encoded,
                commitment,
                ordered,
                position,
            )
        }
        ArchivedCertificateKind::Singleton => {
            let decoded = SharedAgentSnapshotCertificate::decode(certificate).map_err(invalid)?;
            let encoded = decoded.encode();
            let commitment = decoded.commitment();
            let ordered = decoded.claim().ordered().clone();
            let position = decoded.claim().raft_index();
            (
                BoundCertificate::Singleton(decoded),
                encoded,
                commitment,
                ordered,
                position,
            )
        }
    };
    if encoded != certificate
        || commitment != key.certificate
        || position != key.position
        || !key.scope.matches(&ordered)
    {
        return Err(CheckpointArchiveError::CertificateInvalid);
    }
    Ok(bound)
}

#[derive(Clone, Debug)]
pub enum VerifiedArchivedCheckpoint {
    Common(VerifiedSharedAgentCommonSnapshot),
    Singleton(VerifiedSharedAgentSnapshot),
}

/// Promote an archived certificate using the independently trusted committee
/// that was active at that checkpoint. This authenticates the certified
/// claim only: the bundle must still be restored through the host's exact
/// reconstruction and binding checks, and a singleton (AGS) claim remains
/// bound to its source node and store.
pub fn verify_archived_checkpoint(
    key: &ArchivedCheckpointKey,
    certificate: &[u8],
    trusted_committee: &AgentReplicaCommittee,
) -> Result<VerifiedArchivedCheckpoint, CheckpointArchiveError> {
    key.validate()?;
    let invalid = |_| CheckpointArchiveError::CertificateInvalid;
    match bind_certificate(key, certificate)? {
        BoundCertificate::Common(certificate) => certificate
            .verify(trusted_committee, certificate.claim())
            .map(VerifiedArchivedCheckpoint::Common)
            .map_err(invalid),
        BoundCertificate::Singleton(certificate) => certificate
            .verify(trusted_committee, certificate.claim())
            .map(VerifiedArchivedCheckpoint::Singleton)
            .map_err(invalid),
    }
}

/// Configured quotas below the hard ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointArchiveLimits {
    pub max_checkpoint_bytes: usize,
    pub max_segment_bytes: usize,
    pub max_listing: usize,
}

impl CheckpointArchiveLimits {
    pub const MAXIMUM: Self = Self {
        max_checkpoint_bytes: MAX_ARCHIVED_CHECKPOINT_BYTES,
        max_segment_bytes: MAX_ARCHIVED_SEGMENT_BYTES,
        max_listing: MAX_ARCHIVE_LISTING,
    };

    fn validate(self) -> Result<(), CheckpointArchiveError> {
        if self.max_checkpoint_bytes == 0
            || self.max_checkpoint_bytes > MAX_ARCHIVED_CHECKPOINT_BYTES
            || self.max_segment_bytes == 0
            || self.max_segment_bytes > MAX_ARCHIVED_SEGMENT_BYTES
            || self.max_listing == 0
            || self.max_listing > MAX_ARCHIVE_LISTING
        {
            return Err(CheckpointArchiveError::LimitExceeded);
        }
        Ok(())
    }
}

const fn record_overhead(prefix: usize) -> usize {
    prefix + 16 + DIGEST_BYTES
}

/// `prefix || u64 certificate_len || u64 payload_len || digest || sections`.
fn encode_record(prefix: &[u8], certificate: &[u8], payload: &[u8]) -> (Vec<u8>, Hash) {
    let mut output =
        Vec::with_capacity(record_overhead(prefix.len()) + certificate.len() + payload.len());
    output.extend_from_slice(prefix);
    output.extend_from_slice(&(certificate.len() as u64).to_le_bytes());
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let digest = Hash::digest(RECORD_DOMAIN, &[output.as_slice(), certificate, payload]);
    output.extend_from_slice(&digest.0);
    output.extend_from_slice(certificate);
    output.extend_from_slice(payload);
    (output, digest)
}

/// Returns the certificate and payload sections of an exact record.
fn decode_record<'a>(
    prefix: &[u8],
    bytes: &'a [u8],
    max_certificate: usize,
    max_payload: usize,
) -> Result<(&'a [u8], &'a [u8]), CheckpointArchiveError> {
    let corrupt = CheckpointArchiveError::Corrupt;
    let header = prefix.len() + 16;
    if bytes.len() < header + DIGEST_BYTES || &bytes[..prefix.len()] != prefix {
        return Err(corrupt);
    }
    let read_u64 = |at: usize| {
        let mut word = [0; 8];
        word.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(word)
    };
    let certificate_len = read_u64(prefix.len());
    let payload_len = read_u64(prefix.len() + 8);
    if certificate_len > max_certificate as u64 || payload_len > max_payload as u64 {
        // Possibly valid for a larger quota; never parsed under this one.
        return Err(CheckpointArchiveError::LimitExceeded);
    }
    let body = header + DIGEST_BYTES;
    let (certificate_len, payload_len) = (certificate_len as usize, payload_len as usize);
    if bytes.len() != body + certificate_len + payload_len {
        return Err(corrupt);
    }
    let certificate = &bytes[body..body + certificate_len];
    let payload = &bytes[body + certificate_len..];
    let digest = Hash::digest(RECORD_DOMAIN, &[&bytes[..header], certificate, payload]);
    if bytes[header..body] != digest.0 {
        return Err(corrupt);
    }
    Ok((certificate, payload))
}

enum ScannedRecord {
    Checkpoint(ArchivedCertificateKind, u64, Hash),
    Segment(u64, u64),
}

/// Filesystem archive rooted at an existing private directory:
/// `root/<space>/<agent>/<generation>/{c<kind>-<pos>-<cert>,s-<first>-<last>}.vca`.
/// Publication is temp write, file fsync, no-replace hard link, directory
/// fsync. Suitable for tests, a mounted volume, or an archiver node.
pub struct FileCheckpointArchive {
    root: PathBuf,
    limits: CheckpointArchiveLimits,
    sequence: AtomicU64,
}

impl FileCheckpointArchive {
    pub fn open(
        root: &Path,
        limits: CheckpointArchiveLimits,
    ) -> Result<Self, CheckpointArchiveError> {
        limits.validate()?;
        require_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            limits,
            sequence: AtomicU64::new(0),
        })
    }

    fn scope_directory(&self, scope: &ArchiveScope) -> PathBuf {
        self.root
            .join(hex32(&scope.space.0))
            .join(hex32(&scope.agent.0))
            .join(hex32(&scope.generation().0))
    }

    fn ensure_scope_directory(
        &self,
        scope: &ArchiveScope,
    ) -> Result<PathBuf, CheckpointArchiveError> {
        let mut path = self.root.clone();
        for component in [
            hex32(&scope.space.0),
            hex32(&scope.agent.0),
            hex32(&scope.generation().0),
        ] {
            let parent = path.clone();
            path.push(component);
            match fs::create_dir(&path) {
                Ok(()) => sync_directory(&parent)?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => require_directory(&path)?,
                Err(_) => return Err(CheckpointArchiveError::Unavailable),
            }
        }
        Ok(path)
    }

    fn checkpoint_record_bytes(&self, key: &ArchivedCheckpointKey) -> usize {
        record_overhead(key.prefix().len())
            + MAX_ARCHIVED_CERTIFICATE_BYTES
            + self.limits.max_checkpoint_bytes
    }

    fn segment_record_bytes(&self, key: &ArchivedSegmentKey) -> usize {
        record_overhead(key.prefix().len()) + self.limits.max_segment_bytes
    }

    /// Publish exact bytes under `name`, refusing different existing bytes.
    fn publish(
        &self,
        directory: &Path,
        name: &str,
        record: &[u8],
        maximum: usize,
    ) -> Result<bool, CheckpointArchiveError> {
        let path = directory.join(name);
        if let Some(existing) = read_bounded(&path, maximum)? {
            if existing != record {
                return Err(CheckpointArchiveError::Conflict);
            }
            // A prior link may have succeeded before its directory sync
            // failed. Re-establish the barrier before reporting an exact retry.
            sync_directory(directory)?;
            return Ok(false);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let temporary = directory.join(format!(
            "{TEMP_PREFIX}{name}.{}.{sequence}",
            std::process::id()
        ));
        if let Err(error) = write_synced(&temporary, record) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        // `link` never replaces an existing name, unlike `rename`.
        let linked = fs::hard_link(&temporary, &path);
        // An unremoved scratch file is ignored residue, never a record.
        let _ = fs::remove_file(&temporary);
        match linked {
            Ok(()) => {
                sync_directory(directory)?;
                Ok(true)
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let existing =
                    read_bounded(&path, maximum)?.ok_or(CheckpointArchiveError::Unavailable)?;
                if existing != record {
                    return Err(CheckpointArchiveError::Conflict);
                }
                sync_directory(directory)?;
                Ok(false)
            }
            Err(_) => Err(CheckpointArchiveError::Unavailable),
        }
    }

    fn scan(&self, scope: &ArchiveScope) -> Result<Vec<ScannedRecord>, CheckpointArchiveError> {
        scope.validate()?;
        let directory = self.scope_directory(scope);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(CheckpointArchiveError::Unavailable),
            Ok(_) => require_directory(&directory)?,
        }
        let mut records = Vec::new();
        let mut scanned = 0_usize;
        for entry in fs::read_dir(&directory).map_err(|_| CheckpointArchiveError::Unavailable)? {
            let entry = entry.map_err(|_| CheckpointArchiveError::Unavailable)?;
            if scanned == self.limits.max_listing {
                return Err(CheckpointArchiveError::LimitExceeded);
            }
            scanned += 1;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CheckpointArchiveError::Corrupt)?;
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            records.push(parse_record_name(&name).ok_or(CheckpointArchiveError::Corrupt)?);
        }
        Ok(records)
    }

    fn segments(
        &self,
        scope: &ArchiveScope,
    ) -> Result<Vec<ArchivedSegmentKey>, CheckpointArchiveError> {
        let mut segments = self
            .scan(scope)?
            .into_iter()
            .filter_map(|record| match record {
                ScannedRecord::Segment(first, last) => Some(ArchivedSegmentKey {
                    scope: *scope,
                    first,
                    last,
                }),
                ScannedRecord::Checkpoint(..) => None,
            })
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|segment| (segment.first, segment.last));
        if segments.windows(2).any(|pair| pair[0].overlaps(&pair[1])) {
            return Err(CheckpointArchiveError::Corrupt);
        }
        Ok(segments)
    }
}

impl CheckpointArchiveSink for FileCheckpointArchive {
    fn put_checkpoint(
        &self,
        key: &ArchivedCheckpointKey,
        certificate: &[u8],
        bundle: &[u8],
    ) -> Result<ArchiveReceipt, CheckpointArchiveError> {
        key.validate()?;
        if bundle.is_empty() {
            return Err(CheckpointArchiveError::InvalidKey);
        }
        if bundle.len() > self.limits.max_checkpoint_bytes {
            return Err(CheckpointArchiveError::LimitExceeded);
        }
        bind_certificate(key, certificate)?;
        let (record, digest) = encode_record(&key.prefix(), certificate, bundle);
        let directory = self.ensure_scope_directory(&key.scope)?;
        let created = self.publish(
            &directory,
            &key.file_name(),
            &record,
            self.checkpoint_record_bytes(key),
        )?;
        Ok(ArchiveReceipt { digest, created })
    }

    fn put_segment(
        &self,
        key: &ArchivedSegmentKey,
        entries: &[u8],
    ) -> Result<ArchiveReceipt, CheckpointArchiveError> {
        key.validate()?;
        if entries.is_empty() {
            return Err(CheckpointArchiveError::InvalidKey);
        }
        if entries.len() > self.limits.max_segment_bytes {
            return Err(CheckpointArchiveError::LimitExceeded);
        }
        if self
            .segments(&key.scope)?
            .iter()
            .any(|existing| existing != key && existing.overlaps(key))
        {
            return Err(CheckpointArchiveError::Conflict);
        }
        let (record, digest) = encode_record(&key.prefix(), &[], entries);
        let directory = self.ensure_scope_directory(&key.scope)?;
        let created = self.publish(
            &directory,
            &key.file_name(),
            &record,
            self.segment_record_bytes(key),
        )?;
        Ok(ArchiveReceipt { digest, created })
    }
}

impl CheckpointArchiveSource for FileCheckpointArchive {
    fn get_checkpoint(
        &self,
        key: &ArchivedCheckpointKey,
    ) -> Result<Option<ArchivedCheckpoint>, CheckpointArchiveError> {
        key.validate()?;
        let path = self.scope_directory(&key.scope).join(key.file_name());
        let Some(bytes) = read_bounded(&path, self.checkpoint_record_bytes(key))? else {
            return Ok(None);
        };
        let (certificate, bundle) = decode_record(
            &key.prefix(),
            &bytes,
            MAX_ARCHIVED_CERTIFICATE_BYTES,
            self.limits.max_checkpoint_bytes,
        )?;
        if bundle.is_empty() {
            return Err(CheckpointArchiveError::Corrupt);
        }
        bind_certificate(key, certificate).map_err(|_| CheckpointArchiveError::Corrupt)?;
        Ok(Some(ArchivedCheckpoint {
            certificate: certificate.to_vec(),
            bundle: bundle.to_vec(),
        }))
    }

    fn latest_checkpoint(
        &self,
        scope: &ArchiveScope,
    ) -> Result<Option<ArchivedCheckpointKey>, CheckpointArchiveError> {
        Ok(self
            .scan(scope)?
            .into_iter()
            .filter_map(|record| match record {
                ScannedRecord::Checkpoint(kind, position, certificate) => {
                    Some(ArchivedCheckpointKey {
                        scope: *scope,
                        kind,
                        position,
                        certificate,
                    })
                }
                ScannedRecord::Segment(..) => None,
            })
            .max_by(|left, right| {
                left.position
                    .cmp(&right.position)
                    .then_with(|| right.kind.cmp(&left.kind))
                    .then_with(|| right.certificate.0.cmp(&left.certificate.0))
            }))
    }

    fn list_segments_after(
        &self,
        scope: &ArchiveScope,
        position: u64,
        maximum: usize,
    ) -> Result<Vec<ArchivedSegmentKey>, CheckpointArchiveError> {
        if maximum == 0 || maximum > self.limits.max_listing {
            return Err(CheckpointArchiveError::LimitExceeded);
        }
        Ok(self
            .segments(scope)?
            .into_iter()
            .filter(|segment| segment.last > position)
            .take(maximum)
            .collect())
    }

    fn get_segment(
        &self,
        key: &ArchivedSegmentKey,
    ) -> Result<Option<Vec<u8>>, CheckpointArchiveError> {
        key.validate()?;
        let path = self.scope_directory(&key.scope).join(key.file_name());
        let Some(bytes) = read_bounded(&path, self.segment_record_bytes(key))? else {
            return Ok(None);
        };
        let (certificate, entries) =
            decode_record(&key.prefix(), &bytes, 0, self.limits.max_segment_bytes)?;
        if !certificate.is_empty() || entries.is_empty() {
            return Err(CheckpointArchiveError::Corrupt);
        }
        Ok(Some(entries.to_vec()))
    }
}

fn parse_record_name(name: &str) -> Option<ScannedRecord> {
    let stem = name.strip_suffix(RECORD_SUFFIX)?;
    if !stem.is_ascii() {
        return None;
    }
    let bytes = stem.as_bytes();
    if let Some(rest) = stem.strip_prefix("s-") {
        // s-<16>-<16>
        if rest.len() != 33 || rest.as_bytes()[16] != b'-' {
            return None;
        }
        let first = parse_hex_u64(&rest[..16])?;
        let last = parse_hex_u64(&rest[17..])?;
        return (first != 0 && last >= first && last - first < MAX_ARCHIVED_SEGMENT_ENTRIES)
            .then_some(ScannedRecord::Segment(first, last));
    }
    // c<kind>-<16>-<64>
    if bytes.len() != 2 + 1 + 16 + 1 + 64
        || bytes[0] != b'c'
        || bytes[2] != b'-'
        || bytes[19] != b'-'
    {
        return None;
    }
    let kind = ArchivedCertificateKind::from_name(bytes[1])?;
    let position = parse_hex_u64(&stem[3..19])?;
    let certificate = Hash(parse_hex32(&stem[20..])?);
    (position != 0 && certificate != Hash::ZERO).then_some(ScannedRecord::Checkpoint(
        kind,
        position,
        certificate,
    ))
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    (text.len() == 16 && is_lower_hex(text))
        .then(|| u64::from_str_radix(text, 16).ok())
        .flatten()
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !is_lower_hex(text) {
        return None;
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn hex32(bytes: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn require_directory(path: &Path) -> Result<(), CheckpointArchiveError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CheckpointArchiveError::Unavailable)?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(CheckpointArchiveError::Corrupt)
    }
}

fn sync_directory(path: &Path) -> Result<(), CheckpointArchiveError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CheckpointArchiveError::Unavailable)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), CheckpointArchiveError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| CheckpointArchiveError::Unavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CheckpointArchiveError::Unavailable)
}

/// Regular, non-symlink files only; the length is checked before allocation.
fn read_bounded(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, CheckpointArchiveError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CheckpointArchiveError::Unavailable),
    };
    if !metadata.file_type().is_file() {
        return Err(CheckpointArchiveError::Corrupt);
    }
    if metadata.len() > maximum as u64 {
        return Err(CheckpointArchiveError::LimitExceeded);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| CheckpointArchiveError::Unavailable)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(metadata.len() as usize)
        .map_err(|_| CheckpointArchiveError::LimitExceeded)?;
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CheckpointArchiveError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(CheckpointArchiveError::LimitExceeded);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::genesis::{AgentReplicaMember, derive_replica_raft_slot};
    use crate::agent::journal::{
        ArtifactClosureId, CheckpointId, InvocationIndexId, JournalHeadsId, LaneStateId,
        MergeFrontierId, MergeSealId, OrderedBase, OrderedEntryId, RuntimeBinding,
    };
    use crate::agent::shared_commit::{
        ReplicaCommitSignature, SharedAgentCommonSnapshotAncestry, SharedAgentCommonSnapshotClaim,
        SharedAgentSnapshotClaim, SharedLaneProjection, SharedSealedMergeProjection,
    };
    use crate::agent::{
        AgentProfile, AgentReplica, EXECUTION_SEMANTICS_ID, RUNTIME_ABI_ID, ReplicaRole,
    };
    use crate::service::{BlobRef, DeploymentId, NodeId, PrincipalId, ProducerId, ProgramId};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    const SPACE: SpaceId = SpaceId([0x11; 32]);
    const AGENT: AgentId = AgentId([0x22; 32]);
    const GENESIS: AgentJournalGenesisId = AgentJournalGenesisId([0x33; 32]);
    const ADMISSION: AgentGenesisAdmissionId = AgentGenesisAdmissionId::from_bytes([0x34; 32]);
    const SCOPE: ArchiveScope = ArchiveScope {
        space: SPACE,
        agent: AGENT,
        genesis: GENESIS,
        admission: ADMISSION,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-checkpoint-archive-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn archive(directory: &TestDirectory) -> FileCheckpointArchive {
        FileCheckpointArchive::open(
            &directory.0,
            CheckpointArchiveLimits {
                max_checkpoint_bytes: 4096,
                max_segment_bytes: 1024,
                max_listing: 16,
            },
        )
        .unwrap()
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let mut peer = PEER_ID_PREFIX.to_vec();
        peer.extend_from_slice(&key.verifying_key().to_bytes());
        peer
    }

    fn node(key: &SigningKey) -> NodeId {
        NodeId::of_authenticated_peer(&peer_id(key))
    }

    fn committee(voters: &[SigningKey]) -> AgentReplicaCommittee {
        let mut members = voters
            .iter()
            .map(|key| {
                let peer = peer_id(key);
                let public_key = key.verifying_key().to_bytes();
                AgentReplicaMember::new(
                    AgentReplica {
                        node: node(key),
                        principal: PrincipalId::of_public_key(&public_key),
                        role: ReplicaRole::Voter,
                    },
                    peer.clone(),
                    public_key,
                    Some(derive_replica_raft_slot(&peer)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        AgentReplicaCommittee::new(SPACE, AGENT, AgentProfile::Shared, members).unwrap()
    }

    fn lane(byte: u8, state: &[u8]) -> SharedLaneProjection {
        SharedLaneProjection::new(LaneStateId([byte; 32]), BlobRef::of_bytes(state)).unwrap()
    }

    fn ordered(
        committee: &AgentReplicaCommittee,
        raft_index: u64,
        fence: Hash,
    ) -> OrderedCommitClaim {
        OrderedCommitClaim::new(
            GENESIS,
            ADMISSION,
            committee.id(),
            raft_index,
            3,
            OrderedBase {
                index: 7,
                head: Some(OrderedEntryId([0x35; 32])),
            },
            MergeFrontierId([0x36; 32]),
            lane(0x37, b"observed merge state"),
            InvocationIndexId([0x42; 32]),
            RuntimeBinding {
                space: SPACE,
                agent: AGENT,
                deployment: DeploymentId([0x23; 32]),
                program: ProgramId([0x24; 32]),
                producer: ProducerId([0x25; 32]),
                package: BlobRef::of_bytes(b"shared runtime package"),
                runtime_abi: RUNTIME_ABI_ID,
                execution_semantics: EXECUTION_SEMANTICS_ID,
            },
            lane(0x38, b"control state"),
            lane(0x39, b"linear state"),
            InvocationIndexId([0x3a; 32]),
            ArtifactClosureId([0x3b; 32]),
            OrderedBase {
                index: 4,
                head: Some(OrderedEntryId([0x3c; 32])),
            },
            Some(
                SharedSealedMergeProjection::new(
                    MergeSealId([0x3d; 32]),
                    MergeFrontierId([0x3e; 32]),
                    lane(0x3f, b"last sealed merge state"),
                    InvocationIndexId([0x40; 32]),
                )
                .unwrap(),
            ),
            fence,
        )
        .unwrap()
    }

    fn sign(signers: &[&SigningKey], message: Hash) -> Vec<ReplicaCommitSignature> {
        let mut signatures = signers
            .iter()
            .map(|key| {
                ReplicaCommitSignature::new(node(key), key.sign(&message.0).to_bytes()).unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        signatures
    }

    /// Fixed-three AGQ4 certificate signed by voters 1 and 2.
    fn common(raft_index: u64) -> (ArchivedCheckpointKey, Vec<u8>, AgentReplicaCommittee) {
        let voters = [key(1), key(2), key(3)];
        let committee = committee(&voters);
        let ancestry =
            SharedAgentCommonSnapshotAncestry::new(OrderedBase::post_genesis(), Hash([0x49; 32]))
                .unwrap();
        let draft = ordered(&committee, raft_index, Hash([0x41; 32]));
        let ordered = ordered(&committee, raft_index, ancestry.commitment_for(&draft));
        let claim =
            SharedAgentCommonSnapshotClaim::new(ordered, committee.clone(), 1, ancestry).unwrap();
        let message = SharedAgentCommonSnapshotCertificate::signing_message(
            committee.id(),
            claim.commitment(),
        );
        let certificate = SharedAgentCommonSnapshotCertificate::new(
            claim,
            sign(&[&voters[0], &voters[1]], message),
        )
        .unwrap();
        let key = ArchivedCheckpointKey {
            scope: SCOPE,
            kind: ArchivedCertificateKind::Common,
            position: raft_index,
            certificate: certificate.commitment(),
        };
        (key, certificate.encode(), committee)
    }

    /// Single-voter AGS certificate, the production compaction shape.
    fn singleton(raft_index: u64) -> (ArchivedCheckpointKey, Vec<u8>, AgentReplicaCommittee) {
        let voter = key(9);
        let committee = committee(core::slice::from_ref(&voter));
        let claim = SharedAgentSnapshotClaim::new(
            ordered(&committee, raft_index, Hash([0x41; 32])),
            committee.clone(),
            1,
            Hash([0x50; 32]),
            Hash([0x51; 32]),
            JournalHeadsId([0x52; 32]),
            JournalHeadsId([0x53; 32]),
            JournalHeadsId([0x54; 32]),
            CheckpointId([0x55; 32]),
            node(&voter),
            LaneStateId([0x56; 32]),
            LaneStateId([0x57; 32]),
            LaneStateId([0x58; 32]),
            LaneStateId([0x59; 32]),
            InvocationIndexId([0x3a; 32]),
            InvocationIndexId([0x42; 32]),
            InvocationIndexId([0x5a; 32]),
            ArtifactClosureId([0x3b; 32]),
            Hash([0x5b; 32]),
            Hash([0x5c; 32]),
            None,
        )
        .unwrap();
        let message =
            SharedAgentSnapshotCertificate::signing_message(committee.id(), claim.commitment());
        let certificate =
            SharedAgentSnapshotCertificate::new(claim, sign(&[&voter], message)).unwrap();
        let key = ArchivedCheckpointKey {
            scope: SCOPE,
            kind: ArchivedCertificateKind::Singleton,
            position: raft_index,
            certificate: certificate.commitment(),
        };
        (key, certificate.encode(), committee)
    }

    fn segment(first: u64, last: u64) -> ArchivedSegmentKey {
        ArchivedSegmentKey {
            scope: SCOPE,
            first,
            last,
        }
    }

    fn scope_directory(store: &FileCheckpointArchive) -> PathBuf {
        store.scope_directory(&SCOPE)
    }

    #[test]
    fn checkpoint_and_segment_round_trip() {
        let directory = TestDirectory::new("round-trip");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        assert_eq!(store.get_checkpoint(&key), Ok(None));
        let receipt = store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
        assert!(receipt.created);
        assert_eq!(
            store.get_checkpoint(&key).unwrap(),
            Some(ArchivedCheckpoint {
                certificate: certificate.clone(),
                bundle: b"bundle".to_vec(),
            })
        );
        let tail = segment(20, 24);
        assert!(
            store
                .put_segment(&tail, b"entries 20..=24")
                .unwrap()
                .created
        );
        assert_eq!(
            store.get_segment(&tail).unwrap().as_deref(),
            Some(&b"entries 20..=24"[..])
        );
        assert_eq!(store.get_segment(&segment(25, 26)), Ok(None));
        // A reopened store reads the same durable records.
        let reopened = archive(&directory);
        assert_eq!(reopened.latest_checkpoint(&SCOPE), Ok(Some(key)));
        assert_eq!(reopened.list_segments_after(&SCOPE, 19, 8), Ok(vec![tail]));
    }

    #[test]
    fn identical_retries_are_idempotent() {
        let directory = TestDirectory::new("idempotent");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        let first = store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
        let second = store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
        assert!(first.created && !second.created);
        assert_eq!(first.digest, second.digest);
        let tail = segment(20, 21);
        let first = store.put_segment(&tail, b"entries").unwrap();
        let second = store.put_segment(&tail, b"entries").unwrap();
        assert!(first.created && !second.created);
        assert_eq!(first.digest, second.digest);
        assert_eq!(fs::read_dir(scope_directory(&store)).unwrap().count(), 2);
    }

    #[test]
    fn different_bytes_never_overwrite_a_key() {
        let directory = TestDirectory::new("overwrite");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
        assert_eq!(
            store.put_checkpoint(&key, &certificate, b"other bundle"),
            Err(CheckpointArchiveError::Conflict)
        );
        assert_eq!(
            store.get_checkpoint(&key).unwrap().unwrap().bundle,
            b"bundle"
        );

        store.put_segment(&segment(20, 24), b"entries").unwrap();
        assert_eq!(
            store.put_segment(&segment(20, 24), b"forked entries"),
            Err(CheckpointArchiveError::Conflict)
        );
        for overlapping in [segment(22, 30), segment(10, 20), segment(21, 23)] {
            assert_eq!(
                store.put_segment(&overlapping, b"entries"),
                Err(CheckpointArchiveError::Conflict)
            );
        }
        assert_eq!(
            store.list_segments_after(&SCOPE, 0, 8),
            Ok(vec![segment(20, 24)])
        );
    }

    #[test]
    fn tampered_or_moved_records_are_refused() {
        let directory = TestDirectory::new("tamper");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
        let path = scope_directory(&store).join(key.file_name());
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::remove_file(&path).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            store.get_checkpoint(&key),
            Err(CheckpointArchiveError::Corrupt)
        );

        // A valid segment record moved under another range's name.
        store.put_segment(&segment(20, 24), b"entries").unwrap();
        let directory_path = scope_directory(&store);
        fs::rename(
            directory_path.join(segment(20, 24).file_name()),
            directory_path.join(segment(30, 34).file_name()),
        )
        .unwrap();
        assert_eq!(
            store.get_segment(&segment(30, 34)),
            Err(CheckpointArchiveError::Corrupt)
        );

        // A certificate is never accepted under a key it does not match.
        let (other, other_certificate, _) = common(25);
        assert_eq!(
            store.put_checkpoint(&other, &certificate, b"bundle"),
            Err(CheckpointArchiveError::CertificateInvalid)
        );
        let mut retagged = other;
        retagged.kind = ArchivedCertificateKind::Singleton;
        assert_eq!(
            store.put_checkpoint(&retagged, &other_certificate, b"bundle"),
            Err(CheckpointArchiveError::CertificateInvalid)
        );
        let mut foreign = other;
        foreign.scope.admission = AgentGenesisAdmissionId::from_bytes([0x99; 32]);
        assert_eq!(
            store.put_checkpoint(&foreign, &other_certificate, b"bundle"),
            Err(CheckpointArchiveError::CertificateInvalid)
        );
    }

    #[test]
    fn latest_checkpoint_selects_highest_position() {
        let directory = TestDirectory::new("latest");
        let store = archive(&directory);
        assert_eq!(store.latest_checkpoint(&SCOPE), Ok(None));
        let mut keys = Vec::new();
        for index in [25, 40, 19] {
            let (key, certificate, _) = common(index);
            store.put_checkpoint(&key, &certificate, b"bundle").unwrap();
            keys.push(key);
        }
        store.put_segment(&segment(41, 99), b"entries").unwrap();
        assert_eq!(store.latest_checkpoint(&SCOPE), Ok(Some(keys[1])));
        let mut other = SCOPE;
        other.agent = AgentId([0x77; 32]);
        assert_eq!(store.latest_checkpoint(&other), Ok(None));
    }

    #[test]
    fn segments_list_in_order_and_expose_gaps() {
        let directory = TestDirectory::new("segments");
        let store = archive(&directory);
        for (first, last) in [(30, 39), (11, 19), (20, 29), (45, 50)] {
            store
                .put_segment(&segment(first, last), b"entries")
                .unwrap();
        }
        let all = store.list_segments_after(&SCOPE, 0, 16).unwrap();
        assert_eq!(
            all,
            vec![
                segment(11, 19),
                segment(20, 29),
                segment(30, 39),
                segment(45, 50)
            ]
        );
        assert_eq!(
            store.list_segments_after(&SCOPE, 25, 2),
            Ok(vec![segment(20, 29), segment(30, 39)])
        );
        assert_eq!(store.list_segments_after(&SCOPE, 50, 16), Ok(vec![]));
        // From checkpoint 15 the archive covers 16..=39; 40..=44 is a gap.
        assert_eq!(contiguous_archived_end(15, &all), 39);
        assert_eq!(contiguous_archived_end(5, &all), 5);
        assert_eq!(contiguous_archived_end(39, &all), 39);
        assert_eq!(contiguous_archived_end(44, &all), 50);
        assert_eq!(
            store.list_segments_after(&SCOPE, 0, 0),
            Err(CheckpointArchiveError::LimitExceeded)
        );
    }

    #[test]
    fn size_and_range_bounds_refuse_before_mutation() {
        let directory = TestDirectory::new("bounds");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        assert_eq!(
            store.put_checkpoint(&key, &certificate, &[0; 4097]),
            Err(CheckpointArchiveError::LimitExceeded)
        );
        assert_eq!(
            store.put_segment(&segment(1, 2), &[0; 1025]),
            Err(CheckpointArchiveError::LimitExceeded)
        );
        assert_eq!(
            store.put_segment(&segment(1, MAX_ARCHIVED_SEGMENT_ENTRIES + 1), b"entries"),
            Err(CheckpointArchiveError::InvalidKey)
        );
        assert_eq!(
            store.put_segment(&segment(3, 2), b"entries"),
            Err(CheckpointArchiveError::InvalidKey)
        );
        assert_eq!(
            store.put_segment(&segment(1, 2), b""),
            Err(CheckpointArchiveError::InvalidKey)
        );
        let mut zero = key;
        zero.position = 0;
        assert_eq!(
            store.put_checkpoint(&zero, &certificate, b"bundle"),
            Err(CheckpointArchiveError::InvalidKey)
        );
        assert!(!directory.0.join(hex32(&SPACE.0)).exists());

        // A stored record larger than this reader's quota is never loaded.
        store
            .put_checkpoint(&key, &certificate, &[7; 4096])
            .unwrap();
        let small = FileCheckpointArchive::open(
            &directory.0,
            CheckpointArchiveLimits {
                max_checkpoint_bytes: 16,
                max_segment_bytes: 16,
                max_listing: 16,
            },
        )
        .unwrap();
        assert_eq!(
            small.get_checkpoint(&key),
            Err(CheckpointArchiveError::LimitExceeded)
        );
        let tight = FileCheckpointArchive::open(
            &directory.0,
            CheckpointArchiveLimits {
                max_checkpoint_bytes: 16,
                max_segment_bytes: 16,
                max_listing: 1,
            },
        )
        .unwrap();
        store.put_segment(&segment(20, 21), b"entries").unwrap();
        assert_eq!(
            tight.latest_checkpoint(&SCOPE),
            Err(CheckpointArchiveError::LimitExceeded)
        );
        for invalid in [
            CheckpointArchiveLimits {
                max_checkpoint_bytes: 0,
                ..CheckpointArchiveLimits::MAXIMUM
            },
            CheckpointArchiveLimits {
                max_segment_bytes: MAX_ARCHIVED_SEGMENT_BYTES + 1,
                ..CheckpointArchiveLimits::MAXIMUM
            },
        ] {
            assert!(matches!(
                FileCheckpointArchive::open(&directory.0, invalid),
                Err(CheckpointArchiveError::LimitExceeded)
            ));
        }
    }

    #[test]
    fn partial_scratch_files_are_ignored_but_residue_is_not() {
        let directory = TestDirectory::new("crash");
        let store = archive(&directory);
        let (key, certificate, _) = common(19);
        let scope = store.ensure_scope_directory(&SCOPE).unwrap();
        // A crash after a partial temp write and before the link.
        fs::write(
            scope.join(format!("{TEMP_PREFIX}{}.1.0", key.file_name())),
            b"VCA1 partial",
        )
        .unwrap();
        assert_eq!(store.latest_checkpoint(&SCOPE), Ok(None));
        assert_eq!(store.get_checkpoint(&key), Ok(None));
        assert!(
            store
                .put_checkpoint(&key, &certificate, b"bundle")
                .unwrap()
                .created
        );
        assert_eq!(store.latest_checkpoint(&SCOPE), Ok(Some(key)));
        assert_eq!(
            store.get_checkpoint(&key).unwrap().unwrap().bundle,
            b"bundle"
        );

        fs::write(scope.join("cq-0000000000000013-UPPER.vca"), b"x").unwrap();
        assert_eq!(
            store.latest_checkpoint(&SCOPE),
            Err(CheckpointArchiveError::Corrupt)
        );
    }

    #[test]
    fn archived_certificates_verify_only_against_their_committee() {
        let directory = TestDirectory::new("verify");
        let store = archive(&directory);
        let (checkpoint, certificate, trusted) = common(19);
        store
            .put_checkpoint(&checkpoint, &certificate, b"bundle")
            .unwrap();
        let fetched = store.get_checkpoint(&checkpoint).unwrap().unwrap();
        let verified = verify_archived_checkpoint(&checkpoint, &fetched.certificate, &trusted);
        let Ok(VerifiedArchivedCheckpoint::Common(verified)) = verified else {
            panic!("common certificate did not verify");
        };
        assert_eq!(verified.certificate_commitment(), checkpoint.certificate);
        let stranger = committee(&[key(4), key(5), key(6)]);
        assert_eq!(
            verify_archived_checkpoint(&checkpoint, &fetched.certificate, &stranger).err(),
            Some(CheckpointArchiveError::CertificateInvalid)
        );

        let (single, single_certificate, single_committee) = singleton(33);
        store
            .put_checkpoint(&single, &single_certificate, b"physical bundle")
            .unwrap();
        assert!(matches!(
            verify_archived_checkpoint(&single, &single_certificate, &single_committee),
            Ok(VerifiedArchivedCheckpoint::Singleton(_))
        ));
        assert_eq!(
            verify_archived_checkpoint(&single, &single_certificate, &trusted).err(),
            Some(CheckpointArchiveError::CertificateInvalid)
        );
        assert_eq!(store.latest_checkpoint(&SCOPE), Ok(Some(single)));
    }
}
