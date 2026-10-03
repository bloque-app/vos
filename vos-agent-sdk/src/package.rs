//! Clean-generation signed `.vos` package envelopes.
//!
//! An envelope contains exactly one typed manifest and the complete ordered
//! closure of bytes named by that manifest. This module authenticates the
//! byte-level package and its compatibility contract without choosing an
//! Ed25519 implementation. Parsing standard-PVM bytes is intentionally a host
//! tooling boundary for the actor and outer runtime PVMs. Task descriptors do
//! bind their exact PVM bytes to a canonical ProgramId inside this module.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::contract::{
    ActorAbiRange, ActorPackageContract, ExternalStateResourceLimits, RuntimeMigrationPolicy,
    RuntimePackageContract, RuntimeResourceLimits,
};
use crate::method_policy::ActorMethodPolicyArtifact;
use crate::task::TaskDependencySetArtifact;
use crate::wire::CanonicalWire;
use crate::{
    BlobRef, DeploymentId, Hash, LaneSet, MAX_ACTOR_NAME_BYTES, MAX_CATALOG_ARTIFACT_BYTES,
    MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, PackageKind, ProducerId, ProofSystemSet, RUNTIME_ABI_ID,
    RuntimeCapabilities, RuntimeRequirements,
};

/// The only accepted clean-generation `.vos` envelope magic.
pub const PACKAGE_MAGIC: [u8; 4] = *b"VOS3";
/// The only accepted clean-generation `.vos` envelope version.
pub const PACKAGE_VERSION: u16 = 1;
pub const PACKAGE_PUBLIC_KEY_BYTES: usize = 32;
pub const PACKAGE_SIGNATURE_BYTES: usize = 64;
pub const DEPLOYMENT_ID_DOMAIN: &[u8] = b"vos/agent/deployment/v3";
pub const MAX_PACKAGE_NAME_BYTES: usize = MAX_ACTOR_NAME_BYTES;
/// Actor PVM, AAS2, AMP2, AAI1, ATD1, and at most sixteen Task PVMs.
pub const MAX_PACKAGE_ARTIFACTS: usize = 5 + crate::task::MAX_TASK_DEPENDENCIES;

const PACKAGE_SIGNING_MAGIC: [u8; 4] = *b"VSG3";
const BLOB_REF_WIRE_BYTES: usize = 32 + 8;
const PACKAGE_FIXED_WIRE_BYTES: usize = 4 + 2 + 32 + 1 + 4 + MAX_PACKAGE_NAME_BYTES + 512;

/// Absolute encoded-envelope ceiling. It accounts for artifact bytes, one
/// manifest reference and one closure reference per artifact, and fixed fields.
pub const MAX_PACKAGE_ENCODED_BYTES: usize = MAX_CATALOG_ARTIFACT_REFERENCED_BYTES as usize
    + MAX_PACKAGE_ARTIFACTS * (2 * BLOB_REF_WIRE_BYTES + 4)
    + PACKAGE_FIXED_WIRE_BYTES;

/// Producer authentication carried by either typed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageSigning {
    pub producer: ProducerId,
    pub public_key: [u8; PACKAGE_PUBLIC_KEY_BYTES],
    pub signature: [u8; PACKAGE_SIGNATURE_BYTES],
}

impl PackageSigning {
    fn validate_signer(&self) -> Result<(), PackageError> {
        if self.public_key == [0; PACKAGE_PUBLIC_KEY_BYTES] {
            return Err(PackageError::InvalidSignature);
        }
        if ProducerId::of_public_key(&self.public_key) != self.producer {
            return Err(PackageError::WrongProducer);
        }
        Ok(())
    }

    fn validate_signed(&self) -> Result<(), PackageError> {
        self.validate_signer()?;
        if self.signature == [0; PACKAGE_SIGNATURE_BYTES] {
            return Err(PackageError::InvalidSignature);
        }
        Ok(())
    }
}

/// Resources an actor package declares when it needs more than the standard
/// actor profile.
///
/// Every value restates what the signed program already fixes: its length
/// (also [`ActorPackageManifest::program`]'s `len`), its zero-initialised
/// read-write pages (the standard program's heap pages, which contain the
/// actor's allocator arena) and its stack. A declaration therefore adds no
/// execution rule and enters the package identity like any manifest field.
/// It makes a large actor a signed, visible choice of its producer, which an
/// Agent's owner then admits, or refuses, against its own ceilings before
/// installing it. Packages without one keep the released manifest encoding
/// and may carry at most [`crate::STANDARD_ACTOR_PROGRAM_BYTES`] of program
/// at admission for install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorResources {
    pub program_bytes: u32,
    pub heap_bytes: u32,
    pub stack_bytes: u32,
}

impl ActorResources {
    /// Declared page granularity of heap and stack.
    pub const PAGE_BYTES: u32 = 4096;
    /// Largest heap a standard program header can encode (`u16` pages).
    pub const MAX_HEAP_BYTES: u32 = u16::MAX as u32 * Self::PAGE_BYTES;
    /// Largest stack a standard program header can encode (`E3`).
    pub const MAX_STACK_BYTES: u32 = (1 << 24) - 1;

    pub const fn is_valid(self) -> bool {
        self.program_bytes != 0
            && self.program_bytes as usize <= crate::MAX_RUNTIME_PROGRAM_BYTES
            && self.heap_bytes % Self::PAGE_BYTES == 0
            && self.heap_bytes <= Self::MAX_HEAP_BYTES
            && self.stack_bytes <= Self::MAX_STACK_BYTES
    }
}

/// Actor-only manifest. There is deliberately no runtime package or runtime
/// program field: runtime selection is an installation-time compatibility
/// decision and cannot be pinned by an actor package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPackageManifest {
    pub name: String,
    /// Content-addressed canonical standard actor PVM bytes.
    pub program: BlobRef,
    pub contract: ActorPackageContract,
    pub state_lane_schema: BlobRef,
    pub method_policy: BlobRef,
    /// Exact AAI1 operator-facing actor/method introspection artifact.
    pub introspection: BlobRef,
    /// Exact ATD1 typed Task dependency-set artifact. Empty sets still have a
    /// content identity and occupy one closure slot.
    pub task_dependencies: BlobRef,
    /// Explicit producer-selected scheduler dependency. AAI1 Job dispatch is
    /// a client contract and never sets this value implicitly.
    pub scheduling: bool,
    pub requirements: RuntimeRequirements,
    /// Absent for the released actor manifest tag; see [`ActorResources`].
    pub resources: Option<ActorResources>,
    pub signing: PackageSigning,
}

/// AgentRuntime-only manifest. Actor schema, method policy, Task dependencies,
/// and a selected runtime pin are absent by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimePackageManifest {
    pub name: String,
    /// Content-addressed canonical outer standard PVM bytes.
    pub outer_program: BlobRef,
    pub contract: RuntimePackageContract,
    /// Signed experimental extension. Absent for the byte-identical r19 tag;
    /// required for external-state runtimes, refused when unsupported.
    pub external_state_limits: Option<ExternalStateResourceLimits>,
    pub capabilities: RuntimeCapabilities,
    pub signing: PackageSigning,
}

/// Exactly the two clean-generation package kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageManifest {
    Actor(ActorPackageManifest),
    AgentRuntime(AgentRuntimePackageManifest),
}

impl PackageManifest {
    pub fn kind(&self) -> PackageKind {
        match self {
            Self::Actor(manifest) => PackageKind::Actor {
                contract: manifest.contract,
                requirements: manifest.requirements,
            },
            Self::AgentRuntime(manifest) => PackageKind::AgentRuntime {
                contract: manifest.contract,
                capabilities: manifest.capabilities,
            },
        }
    }

    pub fn signing(&self) -> &PackageSigning {
        match self {
            Self::Actor(manifest) => &manifest.signing,
            Self::AgentRuntime(manifest) => &manifest.signing,
        }
    }

    pub fn signing_mut(&mut self) -> &mut PackageSigning {
        match self {
            Self::Actor(manifest) => &mut manifest.signing,
            Self::AgentRuntime(manifest) => &mut manifest.signing,
        }
    }

    fn validate(&self, require_signature: bool) -> Result<(), PackageError> {
        let signing = self.signing();
        if require_signature {
            signing.validate_signed()?;
        } else {
            signing.validate_signer()?;
        }

        let mut references = Vec::new();
        match self {
            Self::Actor(manifest) => {
                validate_name(&manifest.name)?;
                if !manifest.contract.is_valid()
                    || manifest.resources.is_some_and(|resources| {
                        !resources.is_valid()
                            || u64::from(resources.program_bytes) != manifest.program.len
                    })
                {
                    return Err(PackageError::InvalidManifest);
                }
                references
                    .try_reserve_exact(5)
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.program.clone());
                references.push(manifest.state_lane_schema.clone());
                references.push(manifest.method_policy.clone());
                references.push(manifest.introspection.clone());
                references.push(manifest.task_dependencies.clone());
            }
            Self::AgentRuntime(manifest) => {
                validate_name(&manifest.name)?;
                if !manifest.contract.is_valid()
                    || !valid_capabilities(manifest.capabilities)
                    || !valid_external_state_limits(manifest)
                {
                    return Err(PackageError::InvalidManifest);
                }
                references
                    .try_reserve_exact(1)
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.outer_program.clone());
            }
        }
        validate_reference_set(&mut references)?;
        Ok(())
    }
}

fn valid_external_state_limits(manifest: &AgentRuntimePackageManifest) -> bool {
    if manifest.contract.lifecycle_abi == RUNTIME_ABI_ID {
        return manifest.external_state_limits.is_none();
    }
    #[cfg(feature = "experimental-state-blocks")]
    if manifest.contract.lifecycle_abi == crate::state_execution::STATE_EXECUTION_ABI_ID {
        return manifest
            .external_state_limits
            .is_some_and(ExternalStateResourceLimits::is_valid);
    }
    false
}

/// One member of the exact, identity-ordered package closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageArtifact {
    pub identity: BlobRef,
    pub bytes: Vec<u8>,
}

/// Complete signed `.vos` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageEnvelope {
    pub manifest: PackageManifest,
    /// Strictly ordered closure; every manifest reference occurs exactly once.
    pub artifacts: Vec<PackageArtifact>,
}

impl PackageEnvelope {
    /// Validate canonical shape, signer binding, signature presence, and exact
    /// content-addressed closure. This does not perform signature verification.
    pub fn validate_shape(&self) -> Result<(), PackageError> {
        self.manifest.validate(true)?;
        validate_owned_artifacts(&self.artifacts)?;
        let expected = self.expected_references()?;
        validate_exact_closure(&expected, &self.artifacts)?;
        self.validate_actor_artifacts()
    }

    /// Canonical bytes covered by the Ed25519 signature. The signature field
    /// itself is omitted; all other manifest fields and ordered closure
    /// identities are included.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PackageError> {
        self.manifest.validate(false)?;
        validate_owned_artifacts(&self.artifacts)?;
        let expected = self.expected_references()?;
        validate_exact_closure(&expected, &self.artifacts)?;
        self.validate_actor_artifacts()?;
        let capacity = signing_encoded_len(&self.manifest, expected.len())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PackageError::LimitExceeded)?;
        bytes.extend_from_slice(&PACKAGE_SIGNING_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &self.manifest, false);
        encoder.list(&self.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
        });
        if bytes.len() != capacity || bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Verify shape and signature with a caller-supplied Ed25519 provider.
    pub fn verify<V: PackageVerifier>(&self, verifier: &V) -> Result<(), PackageError> {
        self.validate_shape()?;
        let signing = self.manifest.signing();
        let message = self.signing_bytes()?;
        if !verifier.verify(&signing.public_key, &message, &signing.signature) {
            return Err(PackageError::InvalidSignature);
        }
        Ok(())
    }

    /// Whether this package can be selected with a particular runtime.
    pub fn is_compatible_with(
        &self,
        runtime_contract: RuntimePackageContract,
        runtime_capabilities: RuntimeCapabilities,
    ) -> bool {
        self.validate_shape().is_ok()
            && valid_capabilities(runtime_capabilities)
            && self
                .manifest
                .kind()
                .is_compatible_with(runtime_contract, runtime_capabilities)
    }

    pub fn require_compatible_with(
        &self,
        runtime_contract: RuntimePackageContract,
        runtime_capabilities: RuntimeCapabilities,
    ) -> Result<(), PackageError> {
        self.validate_shape()?;
        (valid_capabilities(runtime_capabilities)
            && self
                .manifest
                .kind()
                .is_compatible_with(runtime_contract, runtime_capabilities))
        .then_some(())
        .ok_or(PackageError::IncompatibleRuntime)
    }

    /// Encode the one accepted clean-generation envelope representation.
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        self.validate_shape()?;
        let capacity = envelope_encoded_len(&self.manifest, &self.artifacts)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PackageError::LimitExceeded)?;
        bytes.extend_from_slice(&PACKAGE_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &self.manifest, true);
        encoder.list(&self.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
            encoder.bytes(&artifact.bytes);
        });
        if bytes.len() != capacity || bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Decode with all counts and byte totals checked before artifact contents
    /// are allocated. Unknown tags, old magic, trailing bytes, and noncanonical
    /// ordering are rejected rather than normalized.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackageError> {
        if bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(PACKAGE_MAGIC.len())? != PACKAGE_MAGIC {
            return Err(DecodeError::InvalidTag.into());
        }
        if decoder.u16()? != PACKAGE_VERSION {
            return Err(DecodeError::InvalidTag.into());
        }
        if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform.into());
        }

        let manifest = decode_manifest(&mut decoder)?;
        manifest.validate(true)?;
        let count = decoder.u32()? as usize;
        if count == 0 || count > MAX_PACKAGE_ARTIFACTS {
            return Err(PackageError::LimitExceeded);
        }

        let mut borrowed = Vec::new();
        borrowed
            .try_reserve_exact(count)
            .map_err(|_| PackageError::LimitExceeded)?;
        let mut total = 0u64;
        let mut previous: Option<BlobRef> = None;
        for _ in 0..count {
            let identity = decode_blob(&mut decoder)?;
            if !crate::model::valid_blob(&identity)
                || previous.as_ref().is_some_and(|value| *value >= identity)
            {
                return Err(PackageError::InvalidClosure);
            }
            let artifact_bytes = decoder.bytes_ref_bounded(MAX_CATALOG_ARTIFACT_BYTES as usize)?;
            total = total
                .checked_add(artifact_bytes.len() as u64)
                .ok_or(PackageError::LimitExceeded)?;
            if total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES {
                return Err(PackageError::LimitExceeded);
            }
            if !identity.matches(artifact_bytes) {
                return Err(PackageError::ArtifactMismatch);
            }
            previous = Some(identity.clone());
            borrowed.push((identity, artifact_bytes));
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes.into());
        }

        // All attacker-controlled sizes, identities, and hashes have now been
        // preflighted. Only then copy artifact contents into the owned model.
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(borrowed.len())
            .map_err(|_| PackageError::LimitExceeded)?;
        for (identity, source) in borrowed {
            let mut artifact_bytes = Vec::new();
            artifact_bytes
                .try_reserve_exact(source.len())
                .map_err(|_| PackageError::LimitExceeded)?;
            artifact_bytes.extend_from_slice(source);
            artifacts.push(PackageArtifact {
                identity,
                bytes: artifact_bytes,
            });
        }
        let envelope = Self {
            manifest,
            artifacts,
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    /// Content identity of the exact encoded envelope bytes.
    pub fn package_ref(&self) -> Result<BlobRef, PackageError> {
        Ok(BlobRef::of_bytes(&self.encode()?))
    }

    /// Stable VOS3 deployment identity. It commits the exact signature
    /// message, including the producer and raw public key, while deliberately
    /// excluding the replaceable signature bytes.
    pub fn deployment_id(&self) -> Result<DeploymentId, PackageError> {
        let signing = self.signing_bytes()?;
        let identity = DeploymentId(Hash::digest(DEPLOYMENT_ID_DOMAIN, &[signing.as_slice()]).0);
        if identity == DeploymentId::ZERO {
            Err(PackageError::InvalidManifest)
        } else {
            Ok(identity)
        }
    }

    /// Exact actor standard-PVM bytes, without closure-position assumptions.
    pub fn actor_program_bytes(&self) -> Result<&[u8], PackageError> {
        let manifest = self.validated_actor_manifest()?;
        artifact_bytes(&self.artifacts, &manifest.program)
    }

    /// Exact AgentRuntime outer standard-PVM bytes.
    pub fn runtime_program_bytes(&self) -> Result<&[u8], PackageError> {
        self.validate_shape()?;
        let PackageManifest::AgentRuntime(manifest) = &self.manifest else {
            return Err(PackageError::WrongKind);
        };
        artifact_bytes(&self.artifacts, &manifest.outer_program)
    }

    pub fn actor_schema(&self) -> Result<crate::schema::ParsedSchema, PackageError> {
        let manifest = self.validated_actor_manifest()?;
        crate::schema::decode(artifact_bytes(
            &self.artifacts,
            &manifest.state_lane_schema,
        )?)
        .map_err(|_| PackageError::InvalidActorSchema)
    }

    pub fn constructor_abi(&self) -> Result<Hash, PackageError> {
        self.actor_schema()?
            .constructor_abi()
            .map_err(|_| PackageError::InvalidActorSchema)
    }

    pub fn requires_installation_data(&self) -> Result<bool, PackageError> {
        Ok(self.actor_schema()?.requires_installation_data())
    }

    pub fn actor_method_policy(&self) -> Result<ActorMethodPolicyArtifact, PackageError> {
        let manifest = self.validated_actor_manifest()?;
        ActorMethodPolicyArtifact::decode(artifact_bytes(&self.artifacts, &manifest.method_policy)?)
            .map_err(|_| PackageError::InvalidMethodPolicy)
    }

    pub fn actor_introspection(
        &self,
    ) -> Result<crate::introspection::ActorIntrospectionArtifact, PackageError> {
        let manifest = self.validated_actor_manifest()?;
        crate::introspection::ActorIntrospectionArtifact::decode(artifact_bytes(
            &self.artifacts,
            &manifest.introspection,
        )?)
        .map_err(|_| PackageError::InvalidIntrospection)
    }

    pub fn task_dependency_set(&self) -> Result<TaskDependencySetArtifact, PackageError> {
        let manifest = self.validated_actor_manifest()?;
        TaskDependencySetArtifact::decode(artifact_bytes(
            &self.artifacts,
            &manifest.task_dependencies,
        )?)
        .map_err(|_| PackageError::InvalidTaskDependencies)
    }

    /// Exact standard-PVM bytes for one TaskId in the signed ATD1 set.
    pub fn task_program_bytes(&self, task: crate::TaskId) -> Result<&[u8], PackageError> {
        let task_set = self.task_dependency_set()?;
        let dependency = task_set.dependency(task).ok_or(PackageError::UnknownTask)?;
        artifact_bytes(&self.artifacts, &dependency.artifact)
    }

    fn validated_actor_manifest(&self) -> Result<&ActorPackageManifest, PackageError> {
        self.validate_shape()?;
        let PackageManifest::Actor(manifest) = &self.manifest else {
            return Err(PackageError::WrongKind);
        };
        Ok(manifest)
    }

    fn expected_references(&self) -> Result<Vec<BlobRef>, PackageError> {
        let mut references = Vec::new();
        match &self.manifest {
            PackageManifest::Actor(manifest) => {
                let task_set_bytes = artifact_bytes(&self.artifacts, &manifest.task_dependencies)?;
                let task_set = TaskDependencySetArtifact::decode(task_set_bytes)
                    .map_err(|_| PackageError::InvalidTaskDependencies)?;
                references
                    .try_reserve_exact(5 + task_set.dependencies.len())
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.program.clone());
                references.push(manifest.state_lane_schema.clone());
                references.push(manifest.method_policy.clone());
                references.push(manifest.introspection.clone());
                references.push(manifest.task_dependencies.clone());
                references.extend(
                    task_set
                        .dependencies
                        .iter()
                        .map(|dependency| dependency.artifact.clone()),
                );
            }
            PackageManifest::AgentRuntime(manifest) => {
                references
                    .try_reserve_exact(1)
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.outer_program.clone());
            }
        }
        validate_reference_set(&mut references)?;
        Ok(references)
    }

    fn validate_actor_artifacts(&self) -> Result<(), PackageError> {
        let PackageManifest::Actor(manifest) = &self.manifest else {
            return Ok(());
        };
        let schema_bytes = artifact_bytes(&self.artifacts, &manifest.state_lane_schema)?;
        let actor_schema =
            crate::schema::decode(schema_bytes).map_err(|_| PackageError::InvalidActorSchema)?;
        let policy_bytes = artifact_bytes(&self.artifacts, &manifest.method_policy)?;
        let method_policy = ActorMethodPolicyArtifact::decode(policy_bytes)
            .map_err(|_| PackageError::InvalidMethodPolicy)?;
        if method_policy.actor_schema != manifest.state_lane_schema {
            return Err(PackageError::ActorArtifactMismatch);
        }
        method_policy
            .validate_against_schema(&actor_schema)
            .map_err(|_| PackageError::ActorArtifactMismatch)?;
        let introspection_bytes = artifact_bytes(&self.artifacts, &manifest.introspection)?;
        let introspection =
            crate::introspection::ActorIntrospectionArtifact::decode(introspection_bytes)
                .map_err(|_| PackageError::InvalidIntrospection)?;
        if introspection.actor_schema != manifest.state_lane_schema
            || introspection.method_policy != manifest.method_policy
        {
            return Err(PackageError::ActorArtifactMismatch);
        }
        introspection
            .validate_against_artifact_bytes(schema_bytes, policy_bytes)
            .map_err(|_| PackageError::ActorArtifactMismatch)?;

        let task_set_bytes = artifact_bytes(&self.artifacts, &manifest.task_dependencies)?;
        let task_set = TaskDependencySetArtifact::decode(task_set_bytes)
            .map_err(|_| PackageError::InvalidTaskDependencies)?;
        for dependency in &task_set.dependencies {
            dependency
                .validate_pvm_bytes(artifact_bytes(&self.artifacts, &dependency.artifact)?)
                .map_err(|_| PackageError::InvalidTaskDependencies)?;
        }

        let proof_systems = method_policy
            .proof_systems()
            .map_err(|_| PackageError::ActorArtifactMismatch)?
            .union(
                &task_set
                    .proof_systems()
                    .map_err(|_| PackageError::InvalidTaskDependencies)?,
            )
            .map_err(|_| PackageError::ActorArtifactMismatch)?;
        let derived_requirements = RuntimeRequirements {
            lanes: actor_schema.lanes(),
            // This is a signed producer declaration. AAI Job dispatch does
            // not implicitly enable scheduling.
            scheduling: manifest.scheduling,
            proof_systems,
        };
        if derived_requirements != manifest.requirements {
            return Err(PackageError::ActorArtifactMismatch);
        }
        Ok(())
    }
}

/// Signature verifier supplied by a no_std guest or host. Implementations are
/// expected to perform exact Ed25519 verification for the provided key.
pub trait PackageVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Decode(DecodeError),
    InvalidManifest,
    WrongProducer,
    InvalidSignature,
    InvalidClosure,
    ArtifactMismatch,
    InvalidActorSchema,
    InvalidMethodPolicy,
    InvalidIntrospection,
    InvalidTaskDependencies,
    ActorArtifactMismatch,
    LimitExceeded,
    IncompatibleRuntime,
    WrongKind,
    UnknownTask,
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidManifest => formatter.write_str("invalid package manifest"),
            Self::WrongProducer => formatter.write_str("producer does not match public key"),
            Self::InvalidSignature => formatter.write_str("invalid package signature"),
            Self::InvalidClosure => {
                formatter.write_str("package closure is not exact and canonical")
            }
            Self::ArtifactMismatch => {
                formatter.write_str("package artifact does not match its content identity")
            }
            Self::InvalidActorSchema => formatter.write_str("invalid package actor schema"),
            Self::InvalidMethodPolicy => formatter.write_str("invalid package method policy"),
            Self::InvalidIntrospection => formatter.write_str("invalid actor introspection"),
            Self::InvalidTaskDependencies => {
                formatter.write_str("invalid typed Task dependency set")
            }
            Self::ActorArtifactMismatch => {
                formatter.write_str("package actor artifacts do not agree")
            }
            Self::LimitExceeded => formatter.write_str("package limit exceeded"),
            Self::IncompatibleRuntime => {
                formatter.write_str("package is incompatible with runtime")
            }
            Self::WrongKind => formatter.write_str("wrong package kind for accessor"),
            Self::UnknownTask => formatter.write_str("TaskId is absent from package"),
        }
    }
}

impl core::error::Error for PackageError {}

impl From<DecodeError> for PackageError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

fn validate_name(name: &str) -> Result<(), PackageError> {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_BYTES {
        return Err(PackageError::InvalidManifest);
    }
    Ok(())
}

fn valid_capabilities(capabilities: RuntimeCapabilities) -> bool {
    capabilities.validate().is_ok()
}

fn strictly_sorted(values: &[BlobRef]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_reference_set(references: &mut [BlobRef]) -> Result<(), PackageError> {
    if references.is_empty() || references.len() > MAX_PACKAGE_ARTIFACTS {
        return Err(PackageError::LimitExceeded);
    }
    if references
        .iter()
        .any(|reference| !crate::model::valid_blob(reference))
    {
        return Err(PackageError::InvalidManifest);
    }
    references.sort_unstable();
    if !strictly_sorted(references) {
        return Err(PackageError::InvalidClosure);
    }
    let mut total = 0u64;
    for reference in references {
        total = total
            .checked_add(reference.len)
            .ok_or(PackageError::LimitExceeded)?;
        if total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
    }
    Ok(())
}

fn validate_owned_artifacts(artifacts: &[PackageArtifact]) -> Result<(), PackageError> {
    if artifacts.is_empty() || artifacts.len() > MAX_PACKAGE_ARTIFACTS {
        return Err(PackageError::LimitExceeded);
    }
    let mut total = 0u64;
    let mut previous: Option<&BlobRef> = None;
    for artifact in artifacts {
        if !crate::model::valid_blob(&artifact.identity)
            || previous.is_some_and(|value| value >= &artifact.identity)
        {
            return Err(PackageError::InvalidClosure);
        }
        total = total
            .checked_add(artifact.bytes.len() as u64)
            .ok_or(PackageError::LimitExceeded)?;
        if artifact.bytes.len() as u64 > MAX_CATALOG_ARTIFACT_BYTES
            || total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        {
            return Err(PackageError::LimitExceeded);
        }
        if !artifact.identity.matches(&artifact.bytes) {
            return Err(PackageError::ArtifactMismatch);
        }
        previous = Some(&artifact.identity);
    }
    Ok(())
}

fn validate_exact_closure(
    expected: &[BlobRef],
    artifacts: &[PackageArtifact],
) -> Result<(), PackageError> {
    if artifacts.len() != expected.len()
        || artifacts
            .iter()
            .zip(expected)
            .any(|(artifact, identity)| artifact.identity != *identity)
    {
        return Err(PackageError::InvalidClosure);
    }
    Ok(())
}

fn artifact_bytes<'a>(
    artifacts: &'a [PackageArtifact],
    identity: &BlobRef,
) -> Result<&'a [u8], PackageError> {
    let position = artifacts
        .binary_search_by(|artifact| artifact.identity.cmp(identity))
        .map_err(|_| PackageError::InvalidClosure)?;
    artifacts
        .get(position)
        .map(|artifact| artifact.bytes.as_slice())
        .ok_or(PackageError::InvalidClosure)
}

fn encode_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_requirements(encoder: &mut Encoder<'_>, value: RuntimeRequirements) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, value: RuntimeCapabilities) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
    encoder.u32(value.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    let value = RuntimeCapabilities {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
        max_actors: decoder.u32()?,
    };
    valid_capabilities(value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_actor_contract(encoder: &mut Encoder<'_>, value: ActorPackageContract) {
    encoder.u32(value.actor_abi);
}

fn decode_actor_contract(decoder: &mut Decoder<'_>) -> Result<ActorPackageContract, DecodeError> {
    let value = ActorPackageContract {
        actor_abi: decoder.u32()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_contract(encoder: &mut Encoder<'_>, value: RuntimePackageContract) {
    encoder.fixed(value.lifecycle_abi.as_bytes());
    encoder.u32(value.actor_abis.minimum);
    encoder.u32(value.actor_abis.maximum);
    encoder.fixed(value.control_schema.as_bytes());
    encoder.u32(value.resources.max_runtime_state_bytes);
    encoder.u32(value.resources.max_artifact_references);
    encoder.u64(value.resources.max_artifact_referenced_bytes);
    encoder.u64(value.resources.max_proof_material_bytes);
    encoder.u8(value.migration as u8);
}

fn decode_runtime_contract(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimePackageContract, DecodeError> {
    let value = RuntimePackageContract {
        lifecycle_abi: Hash(decoder.fixed()?),
        actor_abis: ActorAbiRange {
            minimum: decoder.u32()?,
            maximum: decoder.u32()?,
        },
        control_schema: Hash(decoder.fixed()?),
        resources: RuntimeResourceLimits {
            max_runtime_state_bytes: decoder.u32()?,
            max_artifact_references: decoder.u32()?,
            max_artifact_referenced_bytes: decoder.u64()?,
            max_proof_material_bytes: decoder.u64()?,
        },
        migration: match decoder.u8()? {
            0 => RuntimeMigrationPolicy::None,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_signing(encoder: &mut Encoder<'_>, signing: &PackageSigning, include_signature: bool) {
    encoder.fixed(signing.producer.as_bytes());
    encoder.fixed(&signing.public_key);
    if include_signature {
        encoder.0.extend_from_slice(&signing.signature);
    }
}

fn decode_signing(decoder: &mut Decoder<'_>) -> Result<PackageSigning, DecodeError> {
    Ok(PackageSigning {
        producer: ProducerId(decoder.fixed()?),
        public_key: decoder.fixed()?,
        signature: decoder
            .take(PACKAGE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    })
}

fn encode_manifest(encoder: &mut Encoder<'_>, manifest: &PackageManifest, include_signature: bool) {
    match manifest {
        PackageManifest::Actor(manifest) => {
            // Released tag 0 retains its exact byte/signature format; tag 3
            // is the same manifest with its declared resources.
            encoder.u8(if manifest.resources.is_some() { 3 } else { 0 });
            encoder.string(&manifest.name);
            encode_blob(encoder, &manifest.program);
            encode_actor_contract(encoder, manifest.contract);
            encode_blob(encoder, &manifest.state_lane_schema);
            encode_blob(encoder, &manifest.method_policy);
            encode_blob(encoder, &manifest.introspection);
            encode_blob(encoder, &manifest.task_dependencies);
            encoder.bool(manifest.scheduling);
            encode_requirements(encoder, manifest.requirements);
            if let Some(resources) = manifest.resources {
                encoder.u32(resources.program_bytes);
                encoder.u32(resources.heap_bytes);
                encoder.u32(resources.stack_bytes);
            }
            encode_signing(encoder, &manifest.signing, include_signature);
        }
        PackageManifest::AgentRuntime(manifest) => {
            // Released tag 1 retains its exact byte/signature format.
            encoder.u8(if manifest.external_state_limits.is_some() {
                2
            } else {
                1
            });
            encoder.string(&manifest.name);
            encode_blob(encoder, &manifest.outer_program);
            encode_runtime_contract(encoder, manifest.contract);
            encode_capabilities(encoder, manifest.capabilities);
            if let Some(limits) = manifest.external_state_limits {
                encoder.u64(limits.max_rows_per_lane);
                encoder.u64(limits.max_row_bytes_per_lane);
            }
            encode_signing(encoder, &manifest.signing, include_signature);
        }
    }
}

fn decode_actor_manifest(
    decoder: &mut Decoder<'_>,
    declared: bool,
) -> Result<PackageManifest, DecodeError> {
    Ok(PackageManifest::Actor(ActorPackageManifest {
        name: decoder.string_bounded(MAX_PACKAGE_NAME_BYTES)?,
        program: decode_blob(decoder)?,
        contract: decode_actor_contract(decoder)?,
        state_lane_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        introspection: decode_blob(decoder)?,
        task_dependencies: decode_blob(decoder)?,
        scheduling: decoder.bool()?,
        requirements: decode_requirements(decoder)?,
        resources: if declared {
            Some(ActorResources {
                program_bytes: decoder.u32()?,
                heap_bytes: decoder.u32()?,
                stack_bytes: decoder.u32()?,
            })
        } else {
            None
        },
        signing: decode_signing(decoder)?,
    }))
}

fn decode_manifest(decoder: &mut Decoder<'_>) -> Result<PackageManifest, DecodeError> {
    match decoder.u8()? {
        0 => decode_actor_manifest(decoder, false),
        3 => decode_actor_manifest(decoder, true),
        1 => Ok(PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: decoder.string_bounded(MAX_PACKAGE_NAME_BYTES)?,
            outer_program: decode_blob(decoder)?,
            contract: decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
            external_state_limits: None,
            signing: decode_signing(decoder)?,
        })),
        #[cfg(feature = "experimental-state-blocks")]
        2 => Ok(PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: decoder.string_bounded(MAX_PACKAGE_NAME_BYTES)?,
            outer_program: decode_blob(decoder)?,
            contract: decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
            external_state_limits: Some(ExternalStateResourceLimits {
                max_rows_per_lane: decoder.u64()?,
                max_row_bytes_per_lane: decoder.u64()?,
            }),
            signing: decode_signing(decoder)?,
        })),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn manifest_encoded_len(
    manifest: &PackageManifest,
    include_signature: bool,
) -> Result<usize, PackageError> {
    let signature_bytes = if include_signature {
        PACKAGE_SIGNATURE_BYTES
    } else {
        0
    };
    let common = 1usize
        .checked_add(4)
        .and_then(|value| {
            value.checked_add(match manifest {
                PackageManifest::Actor(manifest) => manifest.name.len(),
                PackageManifest::AgentRuntime(manifest) => manifest.name.len(),
            })
        })
        .and_then(|value| value.checked_add(32 + 32 + signature_bytes))
        .ok_or(PackageError::LimitExceeded)?;
    match manifest {
        PackageManifest::Actor(manifest) => common
            // Five exact content references, actor ABI, lanes, explicit
            // scheduling, and the bounded proof-system set.
            .checked_add(
                BLOB_REF_WIRE_BYTES * 5
                    + 4
                    + 1
                    + 1
                    + 1
                    + 1
                    + manifest.requirements.proof_systems.len() * 32
                    + if manifest.resources.is_some() { 12 } else { 0 },
            )
            .ok_or(PackageError::LimitExceeded),
        PackageManifest::AgentRuntime(manifest) => common
            .checked_add(
                BLOB_REF_WIRE_BYTES
                    + 32
                    + 4
                    + 4
                    + 32
                    + 4
                    + 4
                    + 8
                    + 8
                    + 1
                    + 1
                    + 1
                    + 1
                    + manifest.capabilities.proof_systems.len() * 32
                    + if manifest.external_state_limits.is_some() {
                        16
                    } else {
                        0
                    }
                    + 4,
            )
            .ok_or(PackageError::LimitExceeded),
    }
}

fn signing_encoded_len(
    manifest: &PackageManifest,
    artifact_count: usize,
) -> Result<usize, PackageError> {
    (4usize + 2 + 32)
        .checked_add(manifest_encoded_len(manifest, false)?)
        .and_then(|value| value.checked_add(4 + artifact_count * BLOB_REF_WIRE_BYTES))
        .filter(|value| *value <= MAX_PACKAGE_ENCODED_BYTES)
        .ok_or(PackageError::LimitExceeded)
}

fn envelope_encoded_len(
    manifest: &PackageManifest,
    artifacts: &[PackageArtifact],
) -> Result<usize, PackageError> {
    let mut length = (4usize + 2 + 32)
        .checked_add(manifest_encoded_len(manifest, true)?)
        .and_then(|value| value.checked_add(4))
        .ok_or(PackageError::LimitExceeded)?;
    for artifact in artifacts {
        length = length
            .checked_add(BLOB_REF_WIRE_BYTES + 4)
            .and_then(|value| value.checked_add(artifact.bytes.len()))
            .ok_or(PackageError::LimitExceeded)?;
    }
    (length <= MAX_PACKAGE_ENCODED_BYTES)
        .then_some(length)
        .ok_or(PackageError::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::STANDARD_MAX_ACTORS;
    use crate::introspection::{
        ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
    };
    use crate::method_policy::{
        ActorMethodPolicy, AttestationRequirement, AuthorizationPolicySelector,
        IdempotencyRequirement, MethodArgument,
    };
    use crate::schema::{ConstructorContract, ParsedMethod, ParsedSchema};
    use crate::task::{TaskDependency, TaskProofRequirement};

    struct TestVerifier;

    impl PackageVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn test_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(b"vos/test/package-signature/first", &[public_key, message]);
        let second = Hash::digest(b"vos/test/package-signature/second", &[public_key, message]);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    fn unsigned_signing() -> PackageSigning {
        let public_key = [0x5a; PACKAGE_PUBLIC_KEY_BYTES];
        PackageSigning {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; PACKAGE_SIGNATURE_BYTES],
        }
    }

    fn artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn sorted_artifacts(values: &[&[u8]]) -> Vec<PackageArtifact> {
        let mut artifacts: Vec<_> = values.iter().map(|bytes| artifact(bytes)).collect();
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        artifacts
    }

    fn sign(mut envelope: PackageEnvelope) -> PackageEnvelope {
        let message = envelope.signing_bytes().unwrap();
        let public_key = envelope.manifest.signing().public_key;
        envelope.manifest.signing_mut().signature = test_signature(&public_key, &message);
        envelope
    }

    fn actor_package() -> PackageEnvelope {
        let program = b"canonical actor pvm".as_slice();
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: Vec::new(),
            methods: alloc::vec![ParsedMethod {
                source_index: 0,
                name: "increment".into(),
                mode: crate::MethodMode::Merge,
                explicit: true,
            }],
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            methods: alloc::vec![ActorMethodPolicy {
                name: "increment".into(),
                mode: crate::MethodMode::Merge,
                arguments: alloc::vec![MethodArgument {
                    name: "amount".into(),
                    type_identity: "example::IncrementAmount".into(),
                }],
                return_type_identity: "example::IncrementResult".into(),
                authorization_policy: AuthorizationPolicySelector::Capability(crate::CapabilityId(
                    [0x33; 32]
                ),),
                idempotency: IdempotencyRequirement::Required,
                attestation: AttestationRequirement::Required {
                    proof_system: Hash([0x34; 32]),
                },
            }],
        }
        .encode()
        .unwrap();
        let introspection = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            method_policy: BlobRef::of_bytes(&policy),
            actor_doc: "A counter actor.".into(),
            methods: alloc::vec![ActorMethodIntrospection {
                name: "increment".into(),
                doc: "Increment the counter.".into(),
                cli_exposure: CliExposure::Exposed,
                timeout_ms: 0,
                dispatch: MethodDispatch::Sync,
            }],
        }
        .encode()
        .unwrap();
        let task_a = b"task dependency a".as_slice();
        let task_b = b"task dependency b".as_slice();
        let mut dependencies = alloc::vec![
            TaskDependency::new(
                BlobRef::of_bytes(task_a),
                crate::ProgramId::of_pvm(task_a),
                64,
                128,
                TaskProofRequirement::None,
            )
            .unwrap(),
            TaskDependency::new(
                BlobRef::of_bytes(task_b),
                crate::ProgramId::of_pvm(task_b),
                192,
                128,
                TaskProofRequirement::Required {
                    proof_system: Hash([0x35; 32]),
                },
            )
            .unwrap(),
        ];
        dependencies.sort_unstable_by_key(|dependency| dependency.task);
        let task_set = TaskDependencySetArtifact { dependencies }.encode().unwrap();
        sign(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "counter".into(),
                program: BlobRef::of_bytes(program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policy),
                introspection: BlobRef::of_bytes(&introspection),
                task_dependencies: BlobRef::of_bytes(&task_set),
                scheduling: true,
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(crate::StateLane::Merge),
                    scheduling: true,
                    proof_systems: ProofSystemSet::from_sorted(&[
                        Hash([0x34; 32]),
                        Hash([0x35; 32]),
                    ])
                    .unwrap(),
                },
                resources: None,
                signing: unsigned_signing(),
            }),
            artifacts: sorted_artifacts(&[
                program,
                &schema,
                &policy,
                &introspection,
                &task_set,
                task_a,
                task_b,
            ]),
        })
    }

    fn empty_actor_package() -> PackageEnvelope {
        let program = b"canonical zero-handler actor pvm".as_slice();
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: Vec::new(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let introspection = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            method_policy: BlobRef::of_bytes(&policy),
            actor_doc: String::new(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let task_set = TaskDependencySetArtifact {
            dependencies: Vec::new(),
        }
        .encode()
        .unwrap();
        sign(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "passive".into(),
                program: BlobRef::of_bytes(program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policy),
                introspection: BlobRef::of_bytes(&introspection),
                task_dependencies: BlobRef::of_bytes(&task_set),
                scheduling: false,
                requirements: RuntimeRequirements {
                    lanes: LaneSet::NONE,
                    scheduling: false,
                    proof_systems: ProofSystemSet::EMPTY,
                },
                resources: None,
                signing: unsigned_signing(),
            }),
            artifacts: sorted_artifacts(&[program, &schema, &policy, &introspection, &task_set]),
        })
    }

    fn replace_artifact(
        package: &mut PackageEnvelope,
        old_identity: &BlobRef,
        bytes: Vec<u8>,
    ) -> BlobRef {
        let replacement = PackageArtifact {
            identity: BlobRef::of_bytes(&bytes),
            bytes,
        };
        let artifact = package
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.identity == *old_identity)
            .unwrap();
        *artifact = replacement.clone();
        package
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        replacement.identity
    }

    fn runtime_package() -> PackageEnvelope {
        let outer_program = b"canonical outer runtime pvm".as_slice();
        sign(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "standard-agent-runtime".into(),
                external_state_limits: None,
                outer_program: BlobRef::of_bytes(outer_program),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities {
                    lanes: LaneSet::ALL,
                    scheduling: true,
                    proof_systems: ProofSystemSet::from_sorted(&[
                        Hash([0x34; 32]),
                        Hash([0x35; 32]),
                    ])
                    .unwrap(),
                    max_actors: STANDARD_MAX_ACTORS,
                },
                signing: unsigned_signing(),
            }),
            artifacts: sorted_artifacts(&[outer_program]),
        })
    }

    fn encode_unchecked(envelope: &PackageEnvelope) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACKAGE_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &envelope.manifest, true);
        encoder.list(&envelope.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
            encoder.bytes(&artifact.bytes);
        });
        bytes
    }

    fn actor_requirements_offset(manifest: &ActorPackageManifest) -> usize {
        4 + 2 + 32 + 1 + 4 + manifest.name.len() + 4 + BLOB_REF_WIRE_BYTES * 5 + 1
    }

    fn synthetic_reference(index: u32, len: u64) -> BlobRef {
        let mut hash = [0; 32];
        hash[..4].copy_from_slice(&index.to_be_bytes());
        hash[31] = 1;
        BlobRef {
            hash: Hash(hash),
            len,
        }
    }

    #[test]
    fn actor_round_trip_is_canonical_and_content_addressed() {
        let package = actor_package();
        package.verify(&TestVerifier).unwrap();
        let encoded = package.encode().unwrap();
        let decoded = PackageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, package);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(package.package_ref().unwrap(), BlobRef::of_bytes(&encoded));
        assert!(matches!(package.manifest.kind(), PackageKind::Actor { .. }));

        assert_eq!(
            package.actor_program_bytes().unwrap(),
            b"canonical actor pvm"
        );
        assert_eq!(package.actor_schema().unwrap().methods.len(), 1);
        assert_ne!(package.constructor_abi().unwrap(), Hash::ZERO);
        assert!(!package.requires_installation_data().unwrap());
        assert_eq!(package.actor_method_policy().unwrap().methods.len(), 1);
        assert_eq!(package.actor_introspection().unwrap().methods.len(), 1);
        let tasks = package.task_dependency_set().unwrap();
        assert_eq!(tasks.dependencies.len(), 2);
        for dependency in tasks.dependencies {
            dependency
                .validate_pvm_bytes(package.task_program_bytes(dependency.task).unwrap())
                .unwrap();
        }
        assert_eq!(
            package.task_program_bytes(crate::TaskId([0xff; 32])),
            Err(PackageError::UnknownTask)
        );
        assert_eq!(
            package.runtime_program_bytes(),
            Err(PackageError::WrongKind)
        );
    }

    #[test]
    fn deployment_identity_commits_signing_bytes_but_not_signature() {
        let package = actor_package();
        let deployment = package.deployment_id().unwrap();
        assert_ne!(deployment, DeploymentId::ZERO);

        let mut resigned = package.clone();
        resigned.manifest.signing_mut().signature = [0xa5; PACKAGE_SIGNATURE_BYTES];
        assert_eq!(resigned.deployment_id().unwrap(), deployment);

        let mut renamed = package.clone();
        let PackageManifest::Actor(manifest) = &mut renamed.manifest else {
            unreachable!();
        };
        manifest.name = "other-counter".into();
        assert_ne!(renamed.deployment_id().unwrap(), deployment);

        let mut other_producer = package;
        let public_key = [0x6b; PACKAGE_PUBLIC_KEY_BYTES];
        let signing = other_producer.manifest.signing_mut();
        signing.public_key = public_key;
        signing.producer = ProducerId::of_public_key(&public_key);
        assert_ne!(other_producer.deployment_id().unwrap(), deployment);
    }

    #[test]
    fn zero_handler_actor_package_round_trips_but_cannot_name_a_nonempty_schema() {
        let package = empty_actor_package();
        package.verify(&TestVerifier).unwrap();
        let encoded = package.encode().unwrap();
        assert_eq!(PackageEnvelope::decode(&encoded).unwrap(), package);

        let mut mismatch = actor_package();
        let schema = match &mismatch.manifest {
            PackageManifest::Actor(manifest) => manifest.state_lane_schema.clone(),
            PackageManifest::AgentRuntime(_) => unreachable!(),
        };
        let old_policy = match &mismatch.manifest {
            PackageManifest::Actor(manifest) => manifest.method_policy.clone(),
            PackageManifest::AgentRuntime(_) => unreachable!(),
        };
        let empty_policy = ActorMethodPolicyArtifact {
            actor_schema: schema,
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let replacement = replace_artifact(&mut mismatch, &old_policy, empty_policy);
        let PackageManifest::Actor(manifest) = &mut mismatch.manifest else {
            unreachable!();
        };
        manifest.method_policy = replacement;
        assert_eq!(
            mismatch.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );
        assert_eq!(
            PackageEnvelope::decode(&encode_unchecked(&mismatch)),
            Err(PackageError::ActorArtifactMismatch)
        );
    }

    #[test]
    fn actor_schema_and_method_policy_are_semantically_bound_in_the_closure() {
        let package = actor_package();
        let PackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!();
        };
        let policy = ActorMethodPolicyArtifact::decode(
            artifact_bytes(&package.artifacts, &manifest.method_policy).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.actor_schema, manifest.state_lane_schema);
        assert!(policy.requires_attestation());

        let mut renamed = package.clone();
        let old_policy = match &renamed.manifest {
            PackageManifest::Actor(manifest) => manifest.method_policy.clone(),
            PackageManifest::AgentRuntime(_) => unreachable!(),
        };
        let mut policy = ActorMethodPolicyArtifact::decode(
            artifact_bytes(&renamed.artifacts, &old_policy).unwrap(),
        )
        .unwrap();
        policy.methods[0].name = "decrement".into();
        let replacement = replace_artifact(&mut renamed, &old_policy, policy.encode().unwrap());
        let PackageManifest::Actor(manifest) = &mut renamed.manifest else {
            unreachable!();
        };
        manifest.method_policy = replacement;
        assert_eq!(
            renamed.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );
        assert_eq!(
            PackageEnvelope::decode(&encode_unchecked(&renamed)),
            Err(PackageError::ActorArtifactMismatch)
        );

        let mut weaker_proofs = package.clone();
        let PackageManifest::Actor(manifest) = &mut weaker_proofs.manifest else {
            unreachable!();
        };
        manifest.requirements.proof_systems = ProofSystemSet::EMPTY;
        assert_eq!(
            weaker_proofs.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );

        let mut extra_proof = package.clone();
        let PackageManifest::Actor(manifest) = &mut extra_proof.manifest else {
            unreachable!();
        };
        manifest.requirements.proof_systems =
            ProofSystemSet::from_sorted(&[Hash([0x34; 32]), Hash([0x35; 32]), Hash([0x36; 32])])
                .unwrap();
        assert_eq!(
            extra_proof.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );

        let mut scheduling_mismatch = package.clone();
        let PackageManifest::Actor(manifest) = &mut scheduling_mismatch.manifest else {
            unreachable!();
        };
        manifest.scheduling = false;
        assert_eq!(
            scheduling_mismatch.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );

        let mut wrong_lanes = package;
        let PackageManifest::Actor(manifest) = &mut wrong_lanes.manifest else {
            unreachable!();
        };
        manifest.requirements.lanes = LaneSet::of(crate::StateLane::Linear);
        assert_eq!(
            wrong_lanes.validate_shape(),
            Err(PackageError::ActorArtifactMismatch)
        );
    }

    #[test]
    fn job_dispatch_does_not_implicitly_enable_scheduling() {
        let mut package = actor_package();
        let PackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!();
        };
        let old_policy = manifest.method_policy.clone();
        let old_introspection = manifest.introspection.clone();

        let mut policy = ActorMethodPolicyArtifact::decode(
            artifact_bytes(&package.artifacts, &old_policy).unwrap(),
        )
        .unwrap();
        policy.methods[0].return_type_identity =
            crate::introspection::JOB_RETURN_TYPE_IDENTITY.into();
        policy.methods[0].attestation = AttestationRequirement::None;
        let new_policy = replace_artifact(&mut package, &old_policy, policy.encode().unwrap());

        let mut introspection = ActorIntrospectionArtifact::decode(
            artifact_bytes(&package.artifacts, &old_introspection).unwrap(),
        )
        .unwrap();
        introspection.method_policy = new_policy.clone();
        introspection.methods[0].dispatch = MethodDispatch::Job;
        let new_introspection = replace_artifact(
            &mut package,
            &old_introspection,
            introspection.encode().unwrap(),
        );

        let PackageManifest::Actor(manifest) = &mut package.manifest else {
            unreachable!();
        };
        manifest.method_policy = new_policy;
        manifest.introspection = new_introspection;
        manifest.scheduling = false;
        manifest.requirements.scheduling = false;
        manifest.requirements.proof_systems =
            ProofSystemSet::from_sorted(&[Hash([0x35; 32])]).unwrap();
        package.validate_shape().unwrap();
    }

    #[test]
    fn previous_generation_schema_and_policy_wires_have_no_package_fallback() {
        let mut old_schema_package = actor_package();
        let old_schema = match &old_schema_package.manifest {
            PackageManifest::Actor(manifest) => manifest.state_lane_schema.clone(),
            PackageManifest::AgentRuntime(_) => unreachable!(),
        };
        let mut old_schema_bytes = artifact_bytes(&old_schema_package.artifacts, &old_schema)
            .unwrap()
            .to_vec();
        old_schema_bytes[..4].copy_from_slice(b"AAS1");
        let replacement = replace_artifact(&mut old_schema_package, &old_schema, old_schema_bytes);
        let PackageManifest::Actor(manifest) = &mut old_schema_package.manifest else {
            unreachable!();
        };
        manifest.state_lane_schema = replacement;
        assert_eq!(
            old_schema_package.validate_shape(),
            Err(PackageError::InvalidActorSchema)
        );

        let mut package = actor_package();
        let old_policy = match &package.manifest {
            PackageManifest::Actor(manifest) => manifest.method_policy.clone(),
            PackageManifest::AgentRuntime(_) => unreachable!(),
        };
        let replacement = replace_artifact(
            &mut package,
            &old_policy,
            b"VRPW legacy role policy".to_vec(),
        );
        let PackageManifest::Actor(manifest) = &mut package.manifest else {
            unreachable!();
        };
        manifest.method_policy = replacement;
        assert_eq!(
            package.validate_shape(),
            Err(PackageError::InvalidMethodPolicy)
        );
        assert_eq!(
            PackageEnvelope::decode(&encode_unchecked(&package)),
            Err(PackageError::InvalidMethodPolicy)
        );
    }

    #[test]
    fn actor_manifest_cannot_represent_a_runtime_pin() {
        let PackageManifest::Actor(manifest) = &actor_package().manifest else {
            panic!("fixture must be an actor");
        };
        // This exhaustive pattern is intentionally kept without `..`: adding
        // any hidden runtime selection to the actor manifest breaks this test
        // at compile time.
        let ActorPackageManifest {
            name: _,
            program: _,
            contract: _,
            state_lane_schema: _,
            method_policy: _,
            introspection: _,
            task_dependencies: _,
            scheduling: _,
            requirements: _,
            resources: _,
            signing: _,
        } = manifest;
    }

    #[test]
    fn released_runtime_manifest_keeps_exact_layout_and_rejects_external_limits() {
        let mut envelope = runtime_package();
        let PackageManifest::AgentRuntime(manifest) = &envelope.manifest else {
            unreachable!()
        };
        let mut legacy = Vec::new();
        let mut encoder = Encoder(&mut legacy);
        encoder.u8(1);
        encoder.string(&manifest.name);
        encode_blob(&mut encoder, &manifest.outer_program);
        encode_runtime_contract(&mut encoder, manifest.contract);
        encode_capabilities(&mut encoder, manifest.capabilities);
        encode_signing(&mut encoder, &manifest.signing, true);
        let mut current = Vec::new();
        encode_manifest(&mut Encoder(&mut current), &envelope.manifest, true);
        assert_eq!(current, legacy);
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.external_state_limits = Some(ExternalStateResourceLimits {
            max_rows_per_lane: 1,
            max_row_bytes_per_lane: 1,
        });
        assert!(envelope.encode().is_err());
        assert!(PackageEnvelope::decode(&encode_unchecked(&envelope)).is_err());
    }

    #[test]
    fn undeclared_actor_manifest_keeps_the_released_tag_and_bytes() {
        let envelope = actor_package();
        let PackageManifest::Actor(manifest) = &envelope.manifest else {
            unreachable!()
        };
        let mut legacy = Vec::new();
        let mut encoder = Encoder(&mut legacy);
        encoder.u8(0);
        encoder.string(&manifest.name);
        encode_blob(&mut encoder, &manifest.program);
        encode_actor_contract(&mut encoder, manifest.contract);
        encode_blob(&mut encoder, &manifest.state_lane_schema);
        encode_blob(&mut encoder, &manifest.method_policy);
        encode_blob(&mut encoder, &manifest.introspection);
        encode_blob(&mut encoder, &manifest.task_dependencies);
        encoder.bool(manifest.scheduling);
        encode_requirements(&mut encoder, manifest.requirements);
        encode_signing(&mut encoder, &manifest.signing, true);
        let mut current = Vec::new();
        encode_manifest(&mut Encoder(&mut current), &envelope.manifest, true);
        assert_eq!(current, legacy);
        assert_eq!(envelope.encode().unwrap()[4 + 2 + 32], 0);
    }

    fn declared(envelope: &PackageEnvelope, heap_bytes: u32, stack_bytes: u32) -> ActorResources {
        let PackageManifest::Actor(manifest) = &envelope.manifest else {
            unreachable!()
        };
        ActorResources {
            program_bytes: u32::try_from(manifest.program.len).unwrap(),
            heap_bytes,
            stack_bytes,
        }
    }

    #[test]
    fn declared_actor_resources_are_signed_under_their_own_tag() {
        let mut envelope = actor_package();
        let resources = declared(&envelope, 4 * 1024 * 1024, 256 * 1024);
        let PackageManifest::Actor(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.resources = Some(resources);
        let signed = sign(envelope);
        let bytes = signed.encode().unwrap();
        assert_eq!(bytes[4 + 2 + 32], 3);
        assert_eq!(PackageEnvelope::decode(&bytes).unwrap(), signed);
        signed.verify(&TestVerifier).unwrap();
        // The declaration is part of what the producer signs and of the
        // deployment identity: the same package undeclared is another package.
        let mut undeclared = signed.clone();
        let PackageManifest::Actor(manifest) = &mut undeclared.manifest else {
            unreachable!()
        };
        manifest.resources = None;
        assert_ne!(
            undeclared.deployment_id().unwrap(),
            signed.deployment_id().unwrap()
        );
        assert!(undeclared.verify(&TestVerifier).is_err());
    }

    #[test]
    fn declared_actor_resources_must_restate_a_representable_program() {
        let envelope = actor_package();
        let valid = declared(&envelope, 0, 64 * 1024);
        for invalid in [
            // Not the program's own length.
            ActorResources {
                program_bytes: valid.program_bytes + 1,
                ..valid
            },
            ActorResources {
                program_bytes: 0,
                ..valid
            },
            // Heap is whole pages, within the standard header's u16 pages.
            ActorResources {
                heap_bytes: 4097,
                ..valid
            },
            ActorResources {
                heap_bytes: ActorResources::MAX_HEAP_BYTES + ActorResources::PAGE_BYTES,
                ..valid
            },
            ActorResources {
                stack_bytes: ActorResources::MAX_STACK_BYTES + 1,
                ..valid
            },
        ] {
            let mut changed = envelope.clone();
            let PackageManifest::Actor(manifest) = &mut changed.manifest else {
                unreachable!()
            };
            manifest.resources = Some(invalid);
            assert!(changed.encode().is_err(), "{invalid:?}");
            assert!(PackageEnvelope::decode(&encode_unchecked(&changed)).is_err());
        }
        assert!(
            !ActorResources {
                program_bytes: crate::MAX_RUNTIME_PROGRAM_BYTES as u32 + 1,
                ..valid
            }
            .is_valid()
        );
        assert!(
            ActorResources {
                program_bytes: crate::MAX_RUNTIME_PROGRAM_BYTES as u32,
                ..valid
            }
            .is_valid()
        );
        assert!(crate::STANDARD_ACTOR_PROGRAM_BYTES < crate::MAX_RUNTIME_PROGRAM_BYTES);
    }

    #[cfg(not(feature = "experimental-state-blocks"))]
    #[test]
    fn external_manifest_tag_is_refused_without_feature() {
        let mut bytes = runtime_package().encode().unwrap();
        bytes[4 + 2 + 32] = 2;
        assert!(PackageEnvelope::decode(&bytes).is_err());
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn external_manifest_requires_explicit_signed_nonzero_limits() {
        let mut envelope = runtime_package();
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.contract = RuntimePackageContract::experimental_state_blocks();
        assert!(envelope.encode().is_err());
        assert!(PackageEnvelope::decode(&encode_unchecked(&envelope)).is_err());
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.external_state_limits = Some(ExternalStateResourceLimits {
            max_rows_per_lane: 200_000,
            max_row_bytes_per_lane: 1 << 30,
        });
        let signed = sign(envelope);
        let bytes = signed.encode().unwrap();
        assert_eq!(bytes[4 + 2 + 32], 2);
        assert_eq!(PackageEnvelope::decode(&bytes).unwrap(), signed);
        signed.verify(&TestVerifier).unwrap();
        for limit in [
            ExternalStateResourceLimits {
                max_rows_per_lane: 0,
                max_row_bytes_per_lane: 1,
            },
            ExternalStateResourceLimits {
                max_rows_per_lane: 1,
                max_row_bytes_per_lane: 0,
            },
        ] {
            let mut invalid = signed.clone();
            let PackageManifest::AgentRuntime(manifest) = &mut invalid.manifest else {
                unreachable!()
            };
            manifest.external_state_limits = Some(limit);
            assert!(invalid.encode().is_err());
            assert!(PackageEnvelope::decode(&encode_unchecked(&invalid)).is_err());
        }
    }

    #[test]
    fn runtime_round_trip_has_only_its_outer_program_closure() {
        let package = runtime_package();
        package.verify(&TestVerifier).unwrap();
        let encoded = package.encode().unwrap();
        let decoded = PackageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, package);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert!(matches!(
            package.manifest.kind(),
            PackageKind::AgentRuntime { .. }
        ));
        assert_eq!(
            package.runtime_program_bytes().unwrap(),
            b"canonical outer runtime pvm"
        );
        assert_eq!(package.actor_program_bytes(), Err(PackageError::WrongKind));

        let mut with_actor_artifact = package;
        with_actor_artifact
            .artifacts
            .push(artifact(b"actor-only schema"));
        with_actor_artifact
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        assert_eq!(
            with_actor_artifact.validate_shape(),
            Err(PackageError::InvalidClosure)
        );
    }

    #[test]
    fn signature_and_exact_producer_are_fail_closed() {
        let package = actor_package();

        let mut signature_tamper = package.clone();
        signature_tamper.manifest.signing_mut().signature[0] ^= 1;
        assert_eq!(
            signature_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );

        let mut manifest_tamper = package.clone();
        let PackageManifest::Actor(manifest) = &mut manifest_tamper.manifest else {
            unreachable!();
        };
        manifest.name.push('!');
        assert_eq!(
            manifest_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );

        let mut wrong_producer = package.clone();
        wrong_producer.manifest.signing_mut().producer = ProducerId::ZERO;
        assert_eq!(
            wrong_producer.validate_shape(),
            Err(PackageError::WrongProducer)
        );

        let mut wrong_key = package.clone();
        wrong_key.manifest.signing_mut().public_key[0] ^= 1;
        assert_eq!(wrong_key.validate_shape(), Err(PackageError::WrongProducer));

        let mut closure_identity_tamper = package;
        let replacement = artifact(b"different canonical actor pvm");
        let PackageManifest::Actor(manifest) = &mut closure_identity_tamper.manifest else {
            unreachable!();
        };
        let old_program = core::mem::replace(&mut manifest.program, replacement.identity.clone());
        let closure_entry = closure_identity_tamper
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.identity == old_program)
            .unwrap();
        *closure_entry = replacement;
        closure_identity_tamper
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        closure_identity_tamper.validate_shape().unwrap();
        assert_eq!(
            closure_identity_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );
    }

    #[test]
    fn unsigned_shape_can_be_signed_but_not_encoded() {
        let mut package = actor_package();
        package.manifest.signing_mut().signature = [0; PACKAGE_SIGNATURE_BYTES];
        assert!(!package.signing_bytes().unwrap().is_empty());
        assert_eq!(package.encode(), Err(PackageError::InvalidSignature));
    }

    #[test]
    fn closure_rejects_swaps_duplicates_missing_extra_and_mismatched_bytes() {
        let package = actor_package();

        let mut swapped = package.clone();
        swapped.artifacts.swap(0, 1);
        assert_eq!(swapped.validate_shape(), Err(PackageError::InvalidClosure));
        assert_eq!(
            PackageEnvelope::decode(&encode_unchecked(&swapped)),
            Err(PackageError::InvalidClosure)
        );

        let mut duplicate = package.clone();
        duplicate.artifacts[1] = duplicate.artifacts[0].clone();
        assert_eq!(
            duplicate.validate_shape(),
            Err(PackageError::InvalidClosure)
        );

        let mut missing = package.clone();
        missing.artifacts.pop();
        assert_eq!(missing.validate_shape(), Err(PackageError::InvalidClosure));

        let mut extra = package.clone();
        extra.artifacts.push(artifact(b"unreferenced artifact"));
        extra
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        assert_eq!(extra.validate_shape(), Err(PackageError::InvalidClosure));

        let mut mismatched = package;
        mismatched.artifacts[0].bytes[0] ^= 1;
        assert_eq!(
            mismatched.validate_shape(),
            Err(PackageError::ArtifactMismatch)
        );
    }

    #[test]
    fn dependency_order_and_cross_role_aliases_are_rejected() {
        let mut alias = actor_package();
        let PackageManifest::Actor(manifest) = &mut alias.manifest else {
            unreachable!();
        };
        manifest.state_lane_schema = manifest.program.clone();
        assert_eq!(alias.validate_shape(), Err(PackageError::InvalidClosure));

        let package = actor_package();
        let PackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!();
        };
        let targets = [
            manifest.program.clone(),
            manifest.state_lane_schema.clone(),
            manifest.method_policy.clone(),
            manifest.introspection.clone(),
        ];
        for target in targets {
            let mut task_alias = package.clone();
            let task_set_ref = manifest.task_dependencies.clone();
            let target_bytes = artifact_bytes(&task_alias.artifacts, &target)
                .unwrap()
                .to_vec();
            let mut task_set = TaskDependencySetArtifact::decode(
                artifact_bytes(&task_alias.artifacts, &task_set_ref).unwrap(),
            )
            .unwrap();
            let old_task = task_set.dependencies[0].artifact.clone();
            task_set.dependencies[0].artifact = target;
            task_set.dependencies[0].program = crate::ProgramId::of_pvm(&target_bytes);
            task_set.dependencies[0].task = task_set.dependencies[0].derived_task_id().unwrap();
            task_set
                .dependencies
                .sort_unstable_by_key(|dependency| dependency.task);
            let replacement =
                replace_artifact(&mut task_alias, &task_set_ref, task_set.encode().unwrap());
            task_alias
                .artifacts
                .retain(|artifact| artifact.identity != old_task);
            let PackageManifest::Actor(manifest) = &mut task_alias.manifest else {
                unreachable!();
            };
            manifest.task_dependencies = replacement;
            assert_eq!(
                task_alias.validate_shape(),
                Err(PackageError::InvalidClosure),
                "Task PVM alias must fail for every fixed actor role"
            );
        }

        // Attempt to use a Task PVM as the ATD1 role. The bytes cannot decode
        // as the signed dependency set and are rejected before acceptance.
        let mut task_as_set = package.clone();
        let task_set = task_as_set.task_dependency_set().unwrap();
        let task_pvm = task_set.dependencies[0].artifact.clone();
        let PackageManifest::Actor(manifest) = &mut task_as_set.manifest else {
            unreachable!();
        };
        manifest.task_dependencies = task_pvm;
        assert_eq!(
            task_as_set.validate_shape(),
            Err(PackageError::InvalidTaskDependencies)
        );

        // Two dependency roles may not alias one PVM even when their witness
        // windows (and therefore derived TaskIds) remain distinct.
        let mut task_pair_alias = package;
        let PackageManifest::Actor(manifest) = &task_pair_alias.manifest else {
            unreachable!();
        };
        let task_set_ref = manifest.task_dependencies.clone();
        let mut task_set = task_pair_alias.task_dependency_set().unwrap();
        let first_ref = task_set.dependencies[0].artifact.clone();
        let second_ref = task_set.dependencies[1].artifact.clone();
        let first_bytes = artifact_bytes(&task_pair_alias.artifacts, &first_ref)
            .unwrap()
            .to_vec();
        task_set.dependencies[1].artifact = first_ref;
        task_set.dependencies[1].program = crate::ProgramId::of_pvm(&first_bytes);
        task_set.dependencies[1].task = task_set.dependencies[1].derived_task_id().unwrap();
        task_set
            .dependencies
            .sort_unstable_by_key(|dependency| dependency.task);
        let replacement = replace_artifact(
            &mut task_pair_alias,
            &task_set_ref,
            task_set.encode().unwrap(),
        );
        task_pair_alias
            .artifacts
            .retain(|artifact| artifact.identity != second_ref);
        let PackageManifest::Actor(manifest) = &mut task_pair_alias.manifest else {
            unreachable!();
        };
        manifest.task_dependencies = replacement;
        assert_eq!(
            task_pair_alias.validate_shape(),
            Err(PackageError::InvalidClosure)
        );
    }

    #[test]
    fn manifest_reference_limits_are_checked_without_artifact_allocation() {
        let mut long_name = actor_package();
        let PackageManifest::Actor(manifest) = &mut long_name.manifest else {
            unreachable!();
        };
        manifest.name = "x".repeat(MAX_PACKAGE_NAME_BYTES + 1);
        assert_eq!(
            long_name.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut oversized = actor_package();
        let PackageManifest::Actor(manifest) = &mut oversized.manifest else {
            unreachable!();
        };
        manifest.program.len = MAX_CATALOG_ARTIFACT_BYTES + 1;
        assert_eq!(
            oversized.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut too_many = actor_package();
        while too_many.artifacts.len() <= MAX_PACKAGE_ARTIFACTS {
            let index = too_many.artifacts.len() as u32 + 100;
            too_many.artifacts.push(PackageArtifact {
                identity: synthetic_reference(index, 1),
                bytes: alloc::vec![index as u8],
            });
        }
        assert_eq!(too_many.validate_shape(), Err(PackageError::LimitExceeded));
    }

    #[test]
    fn decoder_rejects_hostile_lengths_unknown_tags_and_noncanonical_values() {
        let package = actor_package();
        let encoded = package.encode().unwrap();

        let mut hostile_name = Vec::new();
        hostile_name.extend_from_slice(&PACKAGE_MAGIC);
        hostile_name.extend_from_slice(&PACKAGE_VERSION.to_le_bytes());
        hostile_name.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        hostile_name.push(0);
        hostile_name.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_name),
            Err(PackageError::Decode(DecodeError::LimitExceeded))
        );

        let closure_offset = 4 + 2 + 32 + manifest_encoded_len(&package.manifest, true).unwrap();
        let mut hostile_count = encoded.clone();
        hostile_count[closure_offset..closure_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_count),
            Err(PackageError::LimitExceeded)
        );

        let mut hostile_artifact = encoded.clone();
        let artifact_length_offset = closure_offset + 4 + BLOB_REF_WIRE_BYTES;
        hostile_artifact[artifact_length_offset..artifact_length_offset + 4]
            .copy_from_slice(&((MAX_CATALOG_ARTIFACT_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_artifact),
            Err(PackageError::Decode(DecodeError::LimitExceeded))
        );

        let mut unknown_kind = encoded.clone();
        unknown_kind[4 + 2 + 32] = 0xff;
        assert_eq!(
            PackageEnvelope::decode(&unknown_kind),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );

        let PackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!();
        };
        let requirements_offset = actor_requirements_offset(manifest);
        let mut invalid_lanes = encoded.clone();
        invalid_lanes[requirements_offset] = 0x80;
        assert_eq!(
            PackageEnvelope::decode(&invalid_lanes),
            Err(PackageError::Decode(DecodeError::NonCanonical))
        );
        let mut invalid_bool = encoded;
        invalid_bool[requirements_offset + 1] = 2;
        assert_eq!(
            PackageEnvelope::decode(&invalid_bool),
            Err(PackageError::Decode(DecodeError::NonCanonical))
        );

        let encoded = package.encode().unwrap();
        let mut hostile_proof_count = encoded.clone();
        hostile_proof_count[requirements_offset + 2] = (crate::MAX_PROOF_SYSTEMS + 1) as u8;
        assert_eq!(
            PackageEnvelope::decode(&hostile_proof_count),
            Err(PackageError::Decode(DecodeError::LimitExceeded))
        );

        let mut duplicate_proof = encoded;
        let first = requirements_offset + 3;
        let second = first + 32;
        let first_identity: [u8; 32] = duplicate_proof[first..second].try_into().unwrap();
        duplicate_proof[second..second + 32].copy_from_slice(&first_identity);
        assert_eq!(
            PackageEnvelope::decode(&duplicate_proof),
            Err(PackageError::Decode(DecodeError::NonCanonical))
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes_old_magic_and_unknown_version() {
        let encoded = runtime_package().encode().unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            PackageEnvelope::decode(&trailing),
            Err(PackageError::Decode(DecodeError::TrailingBytes))
        );

        let mut previous_generation = encoded.clone();
        previous_generation[..4].copy_from_slice(b"VOS2");
        assert_eq!(
            PackageEnvelope::decode(&previous_generation),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );

        let mut unknown_version = encoded;
        unknown_version[4..6].copy_from_slice(&(PACKAGE_VERSION + 1).to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&unknown_version),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );
    }

    #[test]
    fn selected_runtime_must_cover_actor_contract_lanes_and_capabilities() {
        let package = actor_package();
        let contract = RuntimePackageContract::canonical();
        let insufficient = RuntimeCapabilities::standard();
        assert!(!package.is_compatible_with(contract, insufficient));
        assert_eq!(
            package.require_compatible_with(contract, insufficient),
            Err(PackageError::IncompatibleRuntime)
        );

        let sufficient = RuntimeCapabilities {
            lanes: LaneSet::ALL,
            scheduling: true,
            proof_systems: ProofSystemSet::from_sorted(&[Hash([0x34; 32]), Hash([0x35; 32])])
                .unwrap(),
            max_actors: STANDARD_MAX_ACTORS,
        };
        assert!(package.is_compatible_with(contract, sufficient));
        package
            .require_compatible_with(contract, sufficient)
            .unwrap();

        let mut incompatible_abi = package;
        let PackageManifest::Actor(manifest) = &mut incompatible_abi.manifest else {
            unreachable!();
        };
        manifest.contract.actor_abi += 1;
        assert!(!incompatible_abi.is_compatible_with(contract, sufficient));

        let invalid_capacity = RuntimeCapabilities {
            max_actors: 0,
            ..sufficient
        };
        assert!(!runtime_package().is_compatible_with(contract, invalid_capacity));
    }
}
