//! Host admission for the clean VOS3 Agent package generation.
//!
//! The portable SDK owns the canonical envelope and artifact contracts. This
//! module adds the host-only checks which deliberately do not belong in a
//! `no_std` guest: raw Ed25519 verification and full standard-PVM parsing.
//! Callers receive opaque admitted values so lifecycle code cannot accidentally
//! persist or execute a merely decoded package.

use alloc::vec::Vec;
use core::fmt;

use vos_agent_sdk::package::{
    ActorPackageManifest, ActorResources, AgentRuntimePackageManifest, PackageEnvelope,
    PackageError, PackageManifest, PackageVerifier,
};
use vos_agent_sdk::{
    AgentProfile, BlobRef, DeploymentId, ProducerId, ProgramId, RuntimeCapabilities,
    RuntimeRequirements, TaskId,
};

/// The package is syntactically VOS3 but is not the one canonical byte
/// representation produced by the SDK codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageAdmissionError {
    PreviousGeneration,
    Package(PackageError),
    NonCanonical,
    WrongKind,
    InvalidActorProgram,
    InvalidTaskProgram(TaskId),
    InvalidRuntimeProgram,
    UnsupportedRuntimeContract,
    UnsupportedProfile,
    IncompatibleRuntime,
    /// The declared resources differ from what the actor program encodes.
    ResourceDeclarationMismatch,
    /// The actor exceeds the installing owner's ceilings, or exceeds the
    /// standard actor profile without declaring its resources.
    ResourceCeiling,
}

impl fmt::Display for PackageAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousGeneration => formatter.write_str(
                "unsupported Agent package generation; only canonical VOS3 packages are accepted",
            ),
            Self::Package(error) => write!(formatter, "invalid VOS3 package: {error}"),
            Self::NonCanonical => formatter.write_str("VOS3 package bytes are not canonical"),
            Self::WrongKind => formatter.write_str("VOS3 package has the wrong package kind"),
            Self::InvalidActorProgram => {
                formatter.write_str("VOS3 actor artifact is not a canonical standard PVM")
            }
            Self::InvalidTaskProgram(task) => {
                write!(
                    formatter,
                    "VOS3 Task artifact {task:?} is not a canonical standard PVM"
                )
            }
            Self::InvalidRuntimeProgram => {
                formatter.write_str("VOS3 AgentRuntime artifact is not a canonical standard PVM")
            }
            Self::UnsupportedRuntimeContract => {
                formatter.write_str("VOS3 AgentRuntime requires a different execution contract")
            }
            Self::UnsupportedProfile => {
                formatter.write_str("VOS3 actor requirements are unsupported by the Agent profile")
            }
            Self::IncompatibleRuntime => {
                formatter.write_str("VOS3 actor package is incompatible with the AgentRuntime")
            }
            Self::ResourceDeclarationMismatch => formatter.write_str(
                "VOS3 actor resource declaration differs from its standard program",
            ),
            Self::ResourceCeiling => formatter.write_str(
                "VOS3 actor exceeds the installation's resource ceilings or must declare its resources",
            ),
        }
    }
}

impl core::error::Error for PackageAdmissionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PackageError> for PackageAdmissionError {
    fn from(value: PackageError) -> Self {
        Self::Package(value)
    }
}

struct RawEd25519Verifier;

impl PackageVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

/// One signature-checked VOS3 AgentActor package whose complete executable
/// closure has passed the host's standard-PVM parser.
#[derive(Clone, Debug)]
pub struct AdmittedActorPackage {
    envelope: PackageEnvelope,
    exact_bytes: Vec<u8>,
    package: BlobRef,
    deployment: DeploymentId,
    program: ProgramId,
}

impl AdmittedActorPackage {
    pub fn envelope(&self) -> &PackageEnvelope {
        &self.envelope
    }

    pub fn manifest(&self) -> &ActorPackageManifest {
        let PackageManifest::Actor(manifest) = &self.envelope.manifest else {
            unreachable!("admitted actor package changed kind")
        };
        manifest
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub const fn package_ref(&self) -> &BlobRef {
        &self.package
    }

    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    pub const fn program(&self) -> ProgramId {
        self.program
    }

    pub fn producer(&self) -> ProducerId {
        self.manifest().signing.producer
    }

    pub fn requirements(&self) -> RuntimeRequirements {
        self.manifest().requirements
    }

    pub fn introspection_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().introspection)
            .expect("admitted package retained its exact closure")
    }

    pub fn state_lane_schema_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().state_lane_schema)
            .expect("admitted package retained its exact closure")
    }

    pub fn method_policy_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().method_policy)
            .expect("admitted package retained its exact closure")
    }

    pub fn program_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().program)
            .expect("admitted package retained its exact closure")
    }

    /// Check installation-time profile and runtime compatibility after both
    /// packages have independently crossed host admission.
    pub fn require_runtime(
        &self,
        profile: AgentProfile,
        runtime: &AdmittedRuntimePackage,
    ) -> Result<(), PackageAdmissionError> {
        if !self.requirements().supported_by(profile) {
            return Err(PackageAdmissionError::UnsupportedProfile);
        }
        self.envelope
            .require_compatible_with(runtime.manifest().contract, runtime.capabilities())
            .map_err(|_| PackageAdmissionError::IncompatibleRuntime)
    }
}

/// One signature-checked VOS3 AgentRuntime package whose outer executable has
/// passed the host's standard-PVM parser and exact Refine host-call allowlist.
#[derive(Clone, Debug)]
pub struct AdmittedRuntimePackage {
    envelope: PackageEnvelope,
    exact_bytes: Vec<u8>,
    package: BlobRef,
    deployment: DeploymentId,
    program: ProgramId,
}

impl AdmittedRuntimePackage {
    pub fn envelope(&self) -> &PackageEnvelope {
        &self.envelope
    }

    pub fn manifest(&self) -> &AgentRuntimePackageManifest {
        let PackageManifest::AgentRuntime(manifest) = &self.envelope.manifest else {
            unreachable!("admitted runtime package changed kind")
        };
        manifest
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub const fn package_ref(&self) -> &BlobRef {
        &self.package
    }

    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    pub const fn program(&self) -> ProgramId {
        self.program
    }

    pub fn producer(&self) -> ProducerId {
        self.manifest().signing.producer
    }

    pub fn capabilities(&self) -> RuntimeCapabilities {
        self.manifest().capabilities
    }

    pub fn program_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().outer_program)
            .expect("admitted package retained its exact closure")
    }
}

/// Ceilings an Agent's owner admits a new actor installation under.
///
/// These are installation policy, applied where an owner submits an Install
/// ([`admit_actor_package_within`]). They are deliberately not applied when a
/// host re-admits a package it already retained (replay, recovery): that path
/// must decide exactly as it did when the package was first installed, so
/// [`admit_actor_package`] depends only on the package bytes. The runtime's
/// own hard maximum, [`vos_agent_sdk::MAX_RUNTIME_PROGRAM_BYTES`], is part of
/// the runtime program and applies at every execution regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorResourceCeilings {
    pub max_program_bytes: u32,
    pub max_heap_bytes: u32,
    pub max_stack_bytes: u32,
}

impl ActorResourceCeilings {
    /// The standard actor profile: today's program limit, and heap and stack
    /// as any standard program header may encode them.
    pub const fn standard() -> Self {
        Self {
            max_program_bytes: vos_agent_sdk::STANDARD_ACTOR_PROGRAM_BYTES as u32,
            max_heap_bytes: ActorResources::MAX_HEAP_BYTES,
            max_stack_bytes: ActorResources::MAX_STACK_BYTES,
        }
    }

    /// The largest ceilings the runtime executes under.
    pub const fn runtime_maximum() -> Self {
        Self {
            max_program_bytes: vos_agent_sdk::MAX_RUNTIME_PROGRAM_BYTES as u32,
            ..Self::standard()
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_program_bytes != 0
            && self.max_program_bytes as usize <= vos_agent_sdk::MAX_RUNTIME_PROGRAM_BYTES
            && self.max_heap_bytes <= ActorResources::MAX_HEAP_BYTES
            && self.max_stack_bytes <= ActorResources::MAX_STACK_BYTES
    }

    /// Whether an actor with these exact program resources may be installed.
    /// Above the standard program size the package must declare them.
    pub const fn admits(self, resources: ActorResources, declared: bool) -> bool {
        self.is_valid()
            && (declared
                || resources.program_bytes as usize <= vos_agent_sdk::STANDARD_ACTOR_PROGRAM_BYTES)
            && resources.program_bytes <= self.max_program_bytes
            && resources.heap_bytes <= self.max_heap_bytes
            && resources.stack_bytes <= self.max_stack_bytes
    }
}

/// What a standard actor program itself fixes: its length, its zero pages
/// (the actor's heap, including its allocator arena) and its stack. `None`
/// when the bytes are not an executor-valid standard program. A package's
/// [`ActorResources`] declaration must equal this.
pub fn actor_program_resources(program: &[u8]) -> Option<ActorResources> {
    let standard = vos_pvm::spi::parse_standard_program(program)?;
    Some(ActorResources {
        program_bytes: u32::try_from(program.len()).ok()?,
        heap_bytes: standard.heap_pages * ActorResources::PAGE_BYTES,
        stack_bytes: standard.stack_size,
    })
}

/// Admit exactly one VOS3 AgentActor envelope.
///
/// A resource declaration, when present, must restate the program exactly.
/// No ceiling is applied here; see [`ActorResourceCeilings`].
pub fn admit_actor_package(bytes: &[u8]) -> Result<AdmittedActorPackage, PackageAdmissionError> {
    admit_actor_package_inner(bytes).map(|(package, _)| package)
}

/// Admit a VOS3 AgentActor envelope for a new installation under the
/// installing owner's `ceilings`.
pub fn admit_actor_package_within(
    bytes: &[u8],
    ceilings: ActorResourceCeilings,
) -> Result<AdmittedActorPackage, PackageAdmissionError> {
    let (package, resources) = admit_actor_package_inner(bytes)?;
    if !ceilings.admits(resources, package.manifest().resources.is_some()) {
        return Err(PackageAdmissionError::ResourceCeiling);
    }
    Ok(package)
}

fn admit_actor_package_inner(
    bytes: &[u8],
) -> Result<(AdmittedActorPackage, ActorResources), PackageAdmissionError> {
    let envelope = decode_and_verify(bytes)?;
    let PackageManifest::Actor(manifest) = &envelope.manifest else {
        return Err(PackageAdmissionError::WrongKind);
    };
    let program_bytes = artifact_bytes(&envelope, &manifest.program)?;
    let resources =
        actor_program_resources(program_bytes).ok_or(PackageAdmissionError::InvalidActorProgram)?;
    if manifest
        .resources
        .is_some_and(|declared| declared != resources)
    {
        return Err(PackageAdmissionError::ResourceDeclarationMismatch);
    }
    let program = ProgramId::of_pvm(program_bytes);
    let tasks = envelope.task_dependency_set()?;
    for dependency in tasks.dependencies {
        let task_program = envelope.task_program_bytes(dependency.task)?;
        if vos_pvm::spi::parse_standard_program(task_program).is_none() {
            return Err(PackageAdmissionError::InvalidTaskProgram(dependency.task));
        }
    }
    let package = BlobRef::of_bytes(bytes);
    let deployment = envelope.deployment_id()?;
    Ok((
        AdmittedActorPackage {
            envelope,
            exact_bytes: bytes.to_vec(),
            package,
            deployment,
            program,
        },
        resources,
    ))
}

/// Admit exactly one VOS3 AgentRuntime envelope.
pub fn admit_runtime_package(
    bytes: &[u8],
) -> Result<AdmittedRuntimePackage, PackageAdmissionError> {
    admit_runtime_with_contract(
        bytes,
        vos_agent_sdk::RUNTIME_ABI_ID,
        &vos_pvm::spi::REFINE_HOST_CALL_ALLOWLIST,
    )
}

/// Distinct type: experimental admission cannot be passed to ordinary r19
/// lifecycle/installation APIs. No conversion to AdmittedRuntimePackage is
/// exposed, even when both contracts are compiled into the same host.
#[cfg(feature = "experimental-state-blocks")]
#[derive(Clone, Debug)]
pub struct AdmittedStateRuntimePackage(AdmittedRuntimePackage);

#[cfg(feature = "experimental-state-blocks")]
impl AdmittedStateRuntimePackage {
    pub fn exact_bytes(&self) -> &[u8] {
        self.0.exact_bytes()
    }

    /// Exact journal identity derived from verified package bytes. This is not
    /// genesis/upgrade authority; the lifecycle owner must admit its selection.
    pub(crate) fn binding(
        &self,
        space: crate::service::SpaceId,
        agent: crate::service::AgentId,
    ) -> Result<super::journal::RuntimeBinding, PackageAdmissionError> {
        use crate::service::{BlobRef, DeploymentId, Hash, ProducerId, ProgramId};
        let binding = super::journal::RuntimeBinding {
            space,
            agent,
            deployment: DeploymentId(self.deployment().0),
            program: ProgramId(self.program().0),
            producer: ProducerId(self.manifest().signing.producer.0),
            package: BlobRef {
                hash: Hash(self.package_ref().hash.0),
                len: self.package_ref().len,
            },
            runtime_abi: Hash(vos_agent_sdk::state_execution::STATE_EXECUTION_ABI_ID.0),
            execution_semantics: Hash(
                vos_agent_sdk::state_execution::STATE_EXECUTION_SEMANTICS_ID.0,
            ),
        };
        binding
            .validate()
            .map_err(|_| PackageAdmissionError::UnsupportedRuntimeContract)?;
        Ok(binding)
    }

    pub fn manifest(&self) -> &AgentRuntimePackageManifest {
        self.0.manifest()
    }

    pub fn external_state_limits(&self) -> vos_agent_sdk::contract::ExternalStateResourceLimits {
        self.manifest()
            .external_state_limits
            .expect("admitted external runtime carries signed limits")
    }

    pub fn program_bytes(&self) -> &[u8] {
        self.0.program_bytes()
    }

    pub fn program(&self) -> ProgramId {
        self.0.program()
    }

    pub fn package_ref(&self) -> &BlobRef {
        self.0.package_ref()
    }

    pub fn deployment(&self) -> DeploymentId {
        self.0.deployment()
    }
}

/// Signature, exact closure and standard PVM admission for the explicit
/// experimental contract. This grants no journal/finality authority and does
/// not open publication, bootstrap or production runtime selection.
#[cfg(feature = "experimental-state-blocks")]
pub fn admit_state_runtime_package(
    bytes: &[u8],
) -> Result<AdmittedStateRuntimePackage, PackageAdmissionError> {
    let mut allowed = vos_pvm::spi::REFINE_HOST_CALL_ALLOWLIST.to_vec();
    allowed.push(u64::from(
        vos_agent_sdk::state_blocks::STATE_BLOCK_FETCH_CALL,
    ));
    let admitted = admit_runtime_with_contract(
        bytes,
        vos_agent_sdk::state_execution::STATE_EXECUTION_ABI_ID,
        &allowed,
    )?;
    if admitted
        .manifest()
        .contract
        .resources
        .max_runtime_state_bytes as usize
        > vos_agent_sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES
    {
        return Err(PackageAdmissionError::UnsupportedRuntimeContract);
    }
    Ok(AdmittedStateRuntimePackage(admitted))
}

fn admit_runtime_with_contract(
    bytes: &[u8],
    expected_abi: vos_agent_sdk::Hash,
    allowed_host_calls: &[u64],
) -> Result<AdmittedRuntimePackage, PackageAdmissionError> {
    let envelope = decode_and_verify(bytes)?;
    let PackageManifest::AgentRuntime(manifest) = &envelope.manifest else {
        return Err(PackageAdmissionError::WrongKind);
    };
    if manifest.contract.lifecycle_abi != expected_abi {
        return Err(PackageAdmissionError::UnsupportedRuntimeContract);
    }
    let program_bytes = artifact_bytes(&envelope, &manifest.outer_program)?;
    if vos_pvm::spi::validate_standard_program_host_calls(program_bytes, allowed_host_calls)
        .is_err()
    {
        return Err(PackageAdmissionError::InvalidRuntimeProgram);
    }
    let program = ProgramId::of_pvm(program_bytes);
    let package = BlobRef::of_bytes(bytes);
    let deployment = envelope.deployment_id()?;
    Ok(AdmittedRuntimePackage {
        envelope,
        exact_bytes: bytes.to_vec(),
        package,
        deployment,
        program,
    })
}

fn decode_and_verify(bytes: &[u8]) -> Result<PackageEnvelope, PackageAdmissionError> {
    if bytes.get(..4) != Some(b"VOS3") {
        return Err(PackageAdmissionError::PreviousGeneration);
    }
    let envelope = PackageEnvelope::decode(bytes)?;
    if envelope.encode()? != bytes {
        return Err(PackageAdmissionError::NonCanonical);
    }
    envelope.verify(&RawEd25519Verifier)?;
    Ok(envelope)
}

fn artifact_bytes<'a>(
    envelope: &'a PackageEnvelope,
    identity: &BlobRef,
) -> Result<&'a [u8], PackageAdmissionError> {
    envelope
        .artifacts
        .binary_search_by(|artifact| artifact.identity.cmp(identity))
        .ok()
        .and_then(|index| envelope.artifacts.get(index))
        .map(|artifact| artifact.bytes.as_slice())
        .ok_or(PackageAdmissionError::Package(PackageError::InvalidClosure))
}

#[cfg(test)]
pub(crate) fn admitted_standard_actor_for_test(
    name: &str,
    lane: vos_agent_sdk::StateLane,
    signing_seed: u8,
) -> AdmittedActorPackage {
    admitted_standard_actor_fixture(name, lane, signing_seed, false)
}

#[cfg(test)]
pub(crate) fn admitted_standard_query_actor_for_test(
    name: &str,
    lane: vos_agent_sdk::StateLane,
    signing_seed: u8,
) -> AdmittedActorPackage {
    admitted_standard_actor_fixture(name, lane, signing_seed, true)
}

#[cfg(test)]
fn admitted_standard_actor_fixture(
    name: &str,
    lane: vos_agent_sdk::StateLane,
    signing_seed: u8,
    public_query: bool,
) -> AdmittedActorPackage {
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::contract::ActorPackageContract;
    use vos_agent_sdk::introspection::{
        ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
    };
    use vos_agent_sdk::method_policy::{
        ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
        AuthorizationPolicySelector, IdempotencyRequirement,
    };
    use vos_agent_sdk::package::{PackageArtifact, PackageSigning};
    use vos_agent_sdk::schema::{
        ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
    };
    use vos_agent_sdk::task::TaskDependencySetArtifact;
    use vos_agent_sdk::wire::CanonicalWire as _;
    use vos_agent_sdk::{FieldPersistence, Hash, LaneSet, MethodMode, ProofSystemSet};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    let mut assembler = Assembler::new();
    let program = if public_query {
        // Done + the three zero lane lengths + one reply byte.
        let output = vec![
            crate::actors::STATUS_DONE,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x63,
        ];
        assembler
            .set_rw_data(output.clone())
            .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
            .load_imm_64(Reg::A1, output.len() as u64)
            .jump_ind(Reg::RA, 0)
            .build_standard()
    } else {
        assembler.load_imm_64(Reg::A0, 1).trap().build_standard()
    };
    let methods = public_query.then(|| ParsedMethod {
        source_index: 0,
        name: "read".into(),
        mode: MethodMode::Query,
        explicit: false,
    });
    let schema = ParsedSchema {
        constructor: ConstructorContract::Forbidden,
        fields: vec![ParsedField::Inline(ParsedInlineField {
            source_index: 0,
            name: "value".into(),
            type_identity: "core::primitive::u64".into(),
            persistence: FieldPersistence::State(lane),
        })],
        methods: methods.into_iter().collect(),
    }
    .encode()
    .unwrap();
    let method_policy = ActorMethodPolicyArtifact {
        actor_schema: BlobRef::of_bytes(&schema),
        methods: public_query
            .then(|| ActorMethodPolicy {
                name: "read".into(),
                mode: MethodMode::Query,
                arguments: Vec::new(),
                return_type_identity: "core::primitive::u8".into(),
                authorization_policy: AuthorizationPolicySelector::Public,
                idempotency: IdempotencyRequirement::NotRequired,
                attestation: AttestationRequirement::None,
            })
            .into_iter()
            .collect(),
    }
    .encode()
    .unwrap();
    let introspection = ActorIntrospectionArtifact {
        actor_schema: BlobRef::of_bytes(&schema),
        method_policy: BlobRef::of_bytes(&method_policy),
        actor_doc: "clean journal lane fixture".into(),
        methods: public_query
            .then(|| ActorMethodIntrospection {
                name: "read".into(),
                doc: String::new(),
                cli_exposure: CliExposure::Exposed,
                timeout_ms: 0,
                dispatch: MethodDispatch::Sync,
            })
            .into_iter()
            .collect(),
    }
    .encode()
    .unwrap();
    let tasks = TaskDependencySetArtifact {
        dependencies: Vec::new(),
    }
    .encode()
    .unwrap();
    let artifact = |bytes: &[u8]| PackageArtifact {
        identity: BlobRef::of_bytes(bytes),
        bytes: bytes.to_vec(),
    };
    let signing = SigningKey::from_bytes(&[signing_seed; 32]);
    let public_key = signing.verifying_key().to_bytes();
    let package_signing = PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
        public_key,
        signature: [0; 64],
    };
    let mut artifacts = vec![
        artifact(&program),
        artifact(&schema),
        artifact(&method_policy),
        artifact(&introspection),
        artifact(&tasks),
    ];
    artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
    let mut package = PackageEnvelope {
        manifest: PackageManifest::Actor(ActorPackageManifest {
            name: name.into(),
            program: BlobRef::of_bytes(&program),
            contract: ActorPackageContract::canonical(),
            state_lane_schema: BlobRef::of_bytes(&schema),
            method_policy: BlobRef::of_bytes(&method_policy),
            introspection: BlobRef::of_bytes(&introspection),
            task_dependencies: BlobRef::of_bytes(&tasks),
            scheduling: false,
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(lane),
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            },
            resources: None,
            signing: package_signing,
        }),
        artifacts,
    };
    let signing_bytes = package.signing_bytes().unwrap();
    package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
    let exact = package.encode().unwrap();
    let admitted = admit_actor_package(&exact).unwrap();
    assert_eq!(admitted.manifest().name, name);
    assert_ne!(admitted.manifest().state_lane_schema.hash, Hash::ZERO);
    admitted
}

#[cfg(test)]
pub(crate) fn admitted_standard_runtime_for_test(
    name: &str,
    signing_seed: u8,
) -> AdmittedRuntimePackage {
    admitted_runtime_program_for_test(
        name,
        signing_seed,
        include_bytes!("../../../vosx/blobs/agent_runtime.pvm"),
    )
}

#[cfg(test)]
pub(crate) fn admitted_runtime_program_for_test(
    name: &str,
    signing_seed: u8,
    program: &[u8],
) -> AdmittedRuntimePackage {
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::contract::RuntimePackageContract;
    use vos_agent_sdk::package::{PackageArtifact, PackageSigning};

    let signing = SigningKey::from_bytes(&[signing_seed; 32]);
    let public_key = signing.verifying_key().to_bytes();
    let mut package = PackageEnvelope {
        manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: name.into(),
            outer_program: BlobRef::of_bytes(program),
            external_state_limits: None,
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            signing: PackageSigning {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: [0; 64],
            },
        }),
        artifacts: vec![PackageArtifact {
            identity: BlobRef::of_bytes(program),
            bytes: program.to_vec(),
        }],
    };
    let signing_bytes = package.signing_bytes().unwrap();
    package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
    admit_runtime_package(&package.encode().unwrap()).unwrap()
}

/// One exact current-ABI response implemented by a physically executed test
/// runtime. Cases are selected by canonical input length; callers must use
/// unique lengths and may copy identity bytes from the read-only input window
/// into an otherwise fixed canonical output.
#[cfg(test)]
pub(crate) struct ScriptedRuntimeCase {
    pub(crate) input: Vec<u8>,
    pub(crate) output: Vec<u8>,
    pub(crate) copies: Vec<ScriptedRuntimeCopy>,
}

#[cfg(test)]
pub(crate) struct ScriptedRuntimeCopy {
    pub(crate) input_offset: usize,
    pub(crate) output_offset: usize,
    pub(crate) len: usize,
}

/// Admit a signed VOS3 package around a small opaque PVM which really reads
/// the current canonical input and returns one of the supplied transitions.
/// This intentionally does not call the native Standard runtime oracle.
#[cfg(test)]
pub(crate) fn admitted_scripted_runtime_for_test(
    name: &str,
    signing_seed: u8,
    cases: Vec<ScriptedRuntimeCase>,
) -> AdmittedRuntimePackage {
    admitted_scripted_runtime_impl(name, signing_seed, cases, false)
}

/// Response-table fixture with physically maintained opaque recovery history.
#[cfg(test)]
pub(crate) fn admitted_recovery_scripted_runtime_for_test(
    name: &str,
    signing_seed: u8,
    cases: Vec<ScriptedRuntimeCase>,
) -> AdmittedRuntimePackage {
    admitted_scripted_runtime_impl(name, signing_seed, cases, true)
}

#[cfg(test)]
fn admitted_scripted_runtime_impl(
    name: &str,
    signing_seed: u8,
    cases: Vec<ScriptedRuntimeCase>,
    recovery: bool,
) -> AdmittedRuntimePackage {
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::contract::RuntimePackageContract;
    use vos_agent_sdk::package::{PackageArtifact, PackageSigning};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    assert!(!cases.is_empty());
    let discriminators = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let same_length = cases
                .iter()
                .enumerate()
                .filter(|(other, candidate)| {
                    *other != index && candidate.input.len() == case.input.len()
                })
                .map(|(_, candidate)| candidate)
                .collect::<Vec<_>>();
            if same_length.is_empty() {
                return None;
            }
            (0..case.input.len())
                .find(|offset| {
                    same_length
                        .iter()
                        .all(|candidate| candidate.input[*offset] != case.input[*offset])
                })
                .map(|offset| (offset, case.input[offset]))
                .or_else(|| panic!("same-length scripted inputs need a byte discriminator"))
        })
        .collect::<Vec<_>>();
    for case in &cases {
        assert!(case.input.len() <= i32::MAX as usize);
        assert!(!case.output.is_empty());
        for copy in &case.copies {
            assert!(copy.len != 0);
            assert!(
                copy.input_offset
                    .checked_add(copy.len)
                    .is_some_and(|end| end <= case.input.len())
            );
            assert!(
                copy.output_offset
                    .checked_add(copy.len)
                    .is_some_and(|end| end <= case.output.len())
            );
        }
    }

    let recovery_program = recovery.then(|| {
        use crate::agent_sdk::protocol::wire::Encoder;
        const MARKER: &[u8; 16] = b"VOS-SCRIPT-R18V1";
        const CAPACITY: usize = 64 * 1024;
        let path = std::env::var_os("AGENT_SCRIPTED_RUNTIME_ELF")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent().unwrap()
                    .join(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
                    .join("agent-recovery-artifacts/scripted/riscv64em-vos/release/custom_linear_agent_runtime.elf")
            });
        let elf = std::fs::read(&path).unwrap_or_else(|error| panic!(
            "read scripted recovery guest {}: {error}; run `just build-agent-recovery-fixture` or set AGENT_SCRIPTED_RUNTIME_ELF",
            path.display(),
        ));
        let mut program = vos_pvm_compiler::link_elf_spi(&elf).expect("link scripted recovery guest");
        let positions: Vec<_> = program.windows(MARKER.len()).enumerate()
            .filter_map(|(offset, bytes)| (bytes == MARKER).then_some(offset)).collect();
        assert_eq!(positions.len(), 1, "one fixed guest configuration region");
        let start = positions[0];
        assert!(program.get(start..start + CAPACITY).is_some());
        assert!(program[start + MARKER.len()..start + CAPACITY].iter().all(|byte| *byte == 0xd5));
        let mut config = MARKER.to_vec();
        let mut encoder = Encoder(&mut config);
        encoder.u32(cases.len().try_into().unwrap());
        for (case, discriminator) in cases.iter().zip(&discriminators) {
            encoder.u32(case.input.len().try_into().unwrap());
            encoder.option(discriminator, |encoder, (offset, value)| {
                encoder.u32((*offset).try_into().unwrap());
                encoder.u8(*value);
            });
            encoder.bytes(&case.output);
            encoder.u32(case.copies.len().try_into().unwrap());
            for copy in &case.copies {
                encoder.u32(copy.input_offset.try_into().unwrap());
                encoder.u32(copy.output_offset.try_into().unwrap());
                encoder.u32(copy.len.try_into().unwrap());
            }
        }
        assert!(config.len() <= CAPACITY, "bounded recovery fixture table");
        program[start..start + config.len()].copy_from_slice(&config);
        vos_pvm::spi::validate_refine_host_calls(&program).expect("clean fixture host calls");
        program
    });
    let mut data = Vec::new();
    let mut output_offsets = Vec::with_capacity(cases.len());
    for case in &cases {
        output_offsets.push(data.len());
        data.extend_from_slice(&case.output);
    }
    let rw_base = 2_u64 * u64::from(vos_pvm::PVM_ZONE_SIZE);
    let mut assembler = Assembler::new();
    assembler.set_rw_data(data);
    for ((case, discriminator), data_offset) in cases.iter().zip(discriminators).zip(output_offsets)
    {
        let copy_instructions = case
            .copies
            .iter()
            .map(|copy| (copy.len / 8 + copy.len % 8).checked_mul(12).unwrap())
            .sum::<usize>();
        let return_instructions = 26_usize;
        let block_len = copy_instructions
            .checked_add(return_instructions)
            .expect("scripted runtime block length");
        let discriminator_len = discriminator.map_or(0, |_| 16_usize);
        assembler.branch_ne_imm(
            Reg::A1,
            i32::try_from(case.input.len()).unwrap(),
            u32::try_from(10 + discriminator_len + block_len).unwrap(),
        );
        if let Some((offset, value)) = discriminator {
            assembler
                .load_ind_u8(Reg::T1, Reg::A0, i32::try_from(offset).unwrap())
                .branch_ne_imm(
                    Reg::T1,
                    i32::from(value),
                    u32::try_from(10 + block_len).unwrap(),
                );
        }
        for copy in &case.copies {
            let mut copied = 0;
            while copy.len - copied >= 8 {
                assembler
                    .load_ind_u64(
                        Reg::T0,
                        Reg::A0,
                        i32::try_from(copy.input_offset + copied).unwrap(),
                    )
                    .store_u64(
                        Reg::T0,
                        u32::try_from(rw_base + (data_offset + copy.output_offset + copied) as u64)
                            .unwrap(),
                    );
                copied += 8;
            }
            while copied < copy.len {
                assembler
                    .load_ind_u8(
                        Reg::T0,
                        Reg::A0,
                        i32::try_from(copy.input_offset + copied).unwrap(),
                    )
                    .store_u8(
                        Reg::T0,
                        u32::try_from(rw_base + (data_offset + copy.output_offset + copied) as u64)
                            .unwrap(),
                    );
                copied += 1;
            }
        }
        assembler
            .load_imm_64(Reg::A0, rw_base + data_offset as u64)
            .load_imm_64(Reg::A1, case.output.len() as u64)
            .jump_ind(Reg::RA, 0);
    }
    assembler.trap();
    let program = recovery_program.unwrap_or_else(|| assembler.build_standard());

    let signing = SigningKey::from_bytes(&[signing_seed; 32]);
    let public_key = signing.verifying_key().to_bytes();
    let mut package = PackageEnvelope {
        manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: name.into(),
            outer_program: BlobRef::of_bytes(&program),
            external_state_limits: None,
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            signing: PackageSigning {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: [0; 64],
            },
        }),
        artifacts: vec![PackageArtifact {
            identity: BlobRef::of_bytes(&program),
            bytes: program,
        }],
    };
    let signing_bytes = package.signing_bytes().unwrap();
    package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
    admit_runtime_package(&package.encode().unwrap()).unwrap()
}

#[cfg(test)]
pub(super) mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos_agent_sdk::introspection::ActorIntrospectionArtifact;
    use vos_agent_sdk::method_policy::ActorMethodPolicyArtifact;
    use vos_agent_sdk::package::{
        ActorPackageManifest, AgentRuntimePackageManifest, PackageArtifact, PackageManifest,
        PackageSigning,
    };
    use vos_agent_sdk::schema::{
        ConstructorContract, ParsedField, ParsedInlineField, ParsedSchema,
    };
    use vos_agent_sdk::task::{TaskDependency, TaskDependencySetArtifact, TaskProofRequirement};
    use vos_agent_sdk::wire::CanonicalWire;
    use vos_agent_sdk::{Hash, LaneSet, ProofSystemSet, StateLane};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::*;

    #[derive(Clone, Copy)]
    struct ActorFixture {
        lane: Option<StateLane>,
        scheduling: bool,
        task: Option<TaskProofRequirement>,
        valid_actor_pvm: bool,
        valid_task_pvm: bool,
    }

    impl Default for ActorFixture {
        fn default() -> Self {
            Self {
                lane: None,
                scheduling: false,
                task: None,
                valid_actor_pvm: true,
                valid_task_pvm: true,
            }
        }
    }

    fn standard_pvm(marker: u64) -> Vec<u8> {
        let mut assembler = Assembler::new();
        assembler.load_imm_64(Reg::A0, marker).trap();
        assembler.build_standard()
    }

    fn artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn signing() -> PackageSigning {
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key = key.verifying_key().to_bytes();
        PackageSigning {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; 64],
        }
    }

    fn sign(mut package: PackageEnvelope) -> PackageEnvelope {
        let message = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = SigningKey::from_bytes(&[0x5a; 32])
            .sign(&message)
            .to_bytes();
        package
    }

    fn actor_package(fixture: ActorFixture) -> PackageEnvelope {
        let actor_program = if fixture.valid_actor_pvm {
            standard_pvm(1)
        } else {
            b"not a standard actor PVM".to_vec()
        };
        actor_package_with(fixture, actor_program, None)
    }

    fn actor_package_with(
        fixture: ActorFixture,
        actor_program: Vec<u8>,
        resources: Option<ActorResources>,
    ) -> PackageEnvelope {
        let fields = fixture
            .lane
            .map(|lane| {
                vec![ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "value".into(),
                    type_identity: "core::primitive::u64".into(),
                    persistence: vos_agent_sdk::FieldPersistence::State(lane),
                })]
            })
            .unwrap_or_default();
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields,
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
            actor_doc: "fixture".into(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();

        let mut proof_systems = ProofSystemSet::EMPTY;
        let mut task_program = None;
        let dependencies = fixture
            .task
            .map(|proof| {
                if let Some(system) = proof.proof_system() {
                    proof_systems.insert(system).unwrap();
                }
                let bytes = if fixture.valid_task_pvm {
                    standard_pvm(2)
                } else {
                    b"not a standard Task PVM".to_vec()
                };
                let dependency = TaskDependency::new(
                    BlobRef::of_bytes(&bytes),
                    ProgramId::of_pvm(&bytes),
                    64,
                    128,
                    proof,
                )
                .unwrap();
                task_program = Some(bytes);
                vec![dependency]
            })
            .unwrap_or_default();
        let tasks = TaskDependencySetArtifact { dependencies }.encode().unwrap();
        let lanes = fixture.lane.map(LaneSet::of).unwrap_or(LaneSet::NONE);
        let mut artifacts = vec![
            artifact(&actor_program),
            artifact(&schema),
            artifact(&policy),
            artifact(&introspection),
            artifact(&tasks),
        ];
        if let Some(task_program) = task_program {
            artifacts.push(artifact(&task_program));
        }
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        sign(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "fixture".into(),
                program: BlobRef::of_bytes(&actor_program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policy),
                introspection: BlobRef::of_bytes(&introspection),
                task_dependencies: BlobRef::of_bytes(&tasks),
                scheduling: fixture.scheduling,
                requirements: RuntimeRequirements {
                    lanes,
                    scheduling: fixture.scheduling,
                    proof_systems,
                },
                resources,
                signing: signing(),
            }),
            artifacts,
        })
    }

    /// A parseable standard program of exactly `bytes` bytes, padded with
    /// read-only data, with the given zero pages and stack.
    fn sized_program(bytes: usize, heap_pages: u32, stack_size: u32) -> Vec<u8> {
        let build = |ro_len: usize| {
            vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
                ro_data: vec![0x5a; ro_len],
                rw_data: Vec::new(),
                heap_pages,
                stack_size,
                code: vos_pvm_program::CodeBlob {
                    jump_table: Vec::new(),
                    code: vec![0],
                    bitmask: vec![1],
                },
            })
            .unwrap()
        };
        let program = build(bytes - build(0).len());
        assert_eq!(program.len(), bytes);
        assert!(vos_pvm::spi::parse_standard_program(&program).is_some());
        program
    }

    #[test]
    fn actor_over_the_standard_program_installs_only_when_declared_and_admitted() {
        const STANDARD: usize = vos_agent_sdk::STANDARD_ACTOR_PROGRAM_BYTES;
        const MAXIMUM: usize = vos_agent_sdk::MAX_RUNTIME_PROGRAM_BYTES;
        const HEAP_PAGES: u32 = 64;
        const STACK: u32 = 256 * 1024;
        // Between the standard profile and the runtime's hard maximum.
        let program = sized_program((STANDARD + MAXIMUM) / 2, HEAP_PAGES, STACK);
        let exact = ActorResources {
            program_bytes: program.len() as u32,
            heap_bytes: HEAP_PAGES * ActorResources::PAGE_BYTES,
            stack_bytes: STACK,
        };
        let package = |resources| {
            actor_package_with(ActorFixture::default(), program.clone(), resources)
                .encode()
                .unwrap()
        };
        let undeclared = package(None);
        let declared = package(Some(exact));
        let owner_raised = ActorResourceCeilings {
            max_program_bytes: MAXIMUM as u32,
            ..ActorResourceCeilings::standard()
        };

        // Re-admission of a retained package (replay, recovery) decides on
        // the bytes alone, exactly as before this change.
        admit_actor_package(&undeclared).unwrap();
        let admitted = admit_actor_package(&declared).unwrap();
        assert_eq!(admitted.manifest().resources, Some(exact));

        // The standard ceilings admit neither: one must declare, the other is
        // above the owner's default ceiling.
        for bytes in [&undeclared, &declared] {
            assert_eq!(
                admit_actor_package_within(bytes, ActorResourceCeilings::standard()).err(),
                Some(PackageAdmissionError::ResourceCeiling)
            );
        }
        // The owner raises the ceiling: the declared actor installs; the
        // undeclared one still must declare.
        let installed = admit_actor_package_within(&declared, owner_raised).unwrap();
        assert_eq!(installed.program(), ProgramId::of_pvm(&program));
        assert_eq!(
            admit_actor_package_within(&undeclared, owner_raised).err(),
            Some(PackageAdmissionError::ResourceCeiling)
        );
        admit_actor_package_within(&declared, ActorResourceCeilings::runtime_maximum()).unwrap();

        // Over any one of the owner's ceilings is refused.
        for ceilings in [
            ActorResourceCeilings {
                max_program_bytes: exact.program_bytes - 1,
                ..owner_raised
            },
            ActorResourceCeilings {
                max_heap_bytes: exact.heap_bytes - ActorResources::PAGE_BYTES,
                ..owner_raised
            },
            ActorResourceCeilings {
                max_stack_bytes: exact.stack_bytes - 1,
                ..owner_raised
            },
        ] {
            assert_eq!(
                admit_actor_package_within(&declared, ceilings).err(),
                Some(PackageAdmissionError::ResourceCeiling)
            );
        }
        // A ceiling above the runtime's hard maximum is not a valid ceiling.
        let beyond = ActorResourceCeilings {
            max_program_bytes: vos_agent_sdk::MAX_RUNTIME_PROGRAM_BYTES as u32 + 1,
            ..owner_raised
        };
        assert!(!beyond.is_valid());
        assert_eq!(
            admit_actor_package_within(&declared, beyond).err(),
            Some(PackageAdmissionError::ResourceCeiling)
        );

        // A declaration must restate the program exactly, on every path.
        for wrong in [
            ActorResources {
                heap_bytes: exact.heap_bytes + ActorResources::PAGE_BYTES,
                ..exact
            },
            ActorResources {
                stack_bytes: exact.stack_bytes - ActorResources::PAGE_BYTES,
                ..exact
            },
        ] {
            let bytes = package(Some(wrong));
            assert_eq!(
                admit_actor_package(&bytes).err(),
                Some(PackageAdmissionError::ResourceDeclarationMismatch)
            );
            assert_eq!(
                admit_actor_package_within(&bytes, owner_raised).err(),
                Some(PackageAdmissionError::ResourceDeclarationMismatch)
            );
        }

        // A standard-size actor is unaffected, declared or not.
        let small = standard_pvm(1);
        let small_undeclared = actor_package_with(ActorFixture::default(), small, None)
            .encode()
            .unwrap();
        admit_actor_package_within(&small_undeclared, ActorResourceCeilings::standard()).unwrap();
    }

    fn runtime_package(capabilities: RuntimeCapabilities, valid_program: bool) -> PackageEnvelope {
        let program = if valid_program {
            standard_pvm(3)
        } else {
            b"not a standard runtime PVM".to_vec()
        };
        runtime_package_with_program(capabilities, program)
    }

    fn runtime_package_with_program(
        capabilities: RuntimeCapabilities,
        program: Vec<u8>,
    ) -> PackageEnvelope {
        sign(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "fixture-runtime".into(),
                external_state_limits: None,
                outer_program: BlobRef::of_bytes(&program),
                contract: RuntimePackageContract::canonical(),
                capabilities,
                signing: signing(),
            }),
            artifacts: vec![artifact(&program)],
        })
    }

    fn admit_actor(fixture: ActorFixture) -> AdmittedActorPackage {
        let bytes = actor_package(fixture).encode().unwrap();
        admit_actor_package(&bytes).unwrap()
    }

    pub(crate) fn admitted_actor_fixture() -> AdmittedActorPackage {
        admit_actor(ActorFixture::default())
    }

    fn admit_runtime(capabilities: RuntimeCapabilities) -> AdmittedRuntimePackage {
        let bytes = runtime_package(capabilities, true).encode().unwrap();
        admit_runtime_package(&bytes).unwrap()
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) const STATE_FIXTURE_LIMITS: vos_agent_sdk::contract::ExternalStateResourceLimits =
        vos_agent_sdk::contract::ExternalStateResourceLimits {
            max_rows_per_lane: 1_000_000,
            max_row_bytes_per_lane: 1 << 30,
        };

    #[cfg(feature = "experimental-state-blocks")]
    fn state_runtime_envelope(program: Vec<u8>) -> PackageEnvelope {
        let mut envelope = runtime_package_with_program(RuntimeCapabilities::standard(), program);
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.contract = RuntimePackageContract::experimental_state_blocks();
        // Explicit fixture policy, not a production deployment default.
        manifest.external_state_limits = Some(STATE_FIXTURE_LIMITS);
        sign(envelope)
    }

    /// Test issuer only; callers still must not treat this as installed journal
    /// authority. Exercise the same admission boundary with compiled fixtures.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn admitted_state_fixture(program: Vec<u8>) -> AdmittedStateRuntimePackage {
        let bytes = state_runtime_envelope(program).encode().unwrap();
        admit_state_runtime_package(&bytes).unwrap()
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn admitted_state_fixture_max_actors(
        program: Vec<u8>,
        max_actors: u32,
    ) -> AdmittedStateRuntimePackage {
        let mut envelope = state_runtime_envelope(program);
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.capabilities.max_actors = max_actors;
        let bytes = sign(envelope).encode().unwrap();
        admit_state_runtime_package(&bytes).unwrap()
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn admitted_state_fixture_row_limits(
        program: Vec<u8>,
        limits: vos_agent_sdk::contract::ExternalStateResourceLimits,
    ) -> AdmittedStateRuntimePackage {
        let mut envelope = state_runtime_envelope(program);
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.external_state_limits = Some(limits);
        admit_state_runtime_package(&sign(envelope).encode().unwrap()).unwrap()
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn admitted_state_fixture_limits(
        program: Vec<u8>,
        lanes: LaneSet,
        state_bytes: u32,
    ) -> AdmittedStateRuntimePackage {
        let mut envelope = state_runtime_envelope(program);
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.capabilities.lanes = lanes;
        manifest.contract.resources.max_runtime_state_bytes = state_bytes;
        let bytes = sign(envelope).encode().unwrap();
        admit_state_runtime_package(&bytes).unwrap()
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn state_runtime_admission_is_explicit_signed_and_disjoint_from_r19() {
        use vos_agent_sdk::state_blocks::STATE_BLOCK_FETCH_CALL;
        let program = Assembler::new()
            .ecalli(STATE_BLOCK_FETCH_CALL)
            .trap()
            .build_standard();
        let envelope = state_runtime_envelope(program.clone());
        let bytes = envelope.encode().unwrap();
        let admitted = admit_state_runtime_package(&bytes).unwrap();
        assert_eq!(admitted.program_bytes(), program);
        assert_eq!(admitted.program(), ProgramId::of_pvm(&program));
        assert_eq!(*admitted.package_ref(), BlobRef::of_bytes(&bytes));
        assert_eq!(admitted.deployment(), envelope.deployment_id().unwrap());
        assert_eq!(
            admitted.external_state_limits().max_rows_per_lane,
            1_000_000
        );
        for change_bytes in [false, true] {
            let mut tampered = envelope.clone();
            let PackageManifest::AgentRuntime(manifest) = &mut tampered.manifest else {
                unreachable!()
            };
            let limits = manifest.external_state_limits.as_mut().unwrap();
            if change_bytes {
                limits.max_row_bytes_per_lane -= 1;
            } else {
                limits.max_rows_per_lane -= 1;
            }
            assert_eq!(
                admit_state_runtime_package(&tampered.encode().unwrap()).unwrap_err(),
                PackageAdmissionError::Package(PackageError::InvalidSignature)
            );
            let resigned = sign(tampered);
            let changed = admit_state_runtime_package(&resigned.encode().unwrap()).unwrap();
            assert_ne!(changed.deployment(), admitted.deployment());
            assert_ne!(changed.package_ref(), admitted.package_ref());
            assert_ne!(
                changed.external_state_limits(),
                admitted.external_state_limits()
            );
        }
        assert_eq!(
            admitted.manifest().contract,
            RuntimePackageContract::experimental_state_blocks()
        );
        let mut over_budget = envelope.clone();
        let PackageManifest::AgentRuntime(manifest) = &mut over_budget.manifest else {
            unreachable!()
        };
        manifest.contract.resources.max_runtime_state_bytes =
            vos_agent_sdk::MAX_RUNTIME_STATE_BYTES as u32;
        let over_budget = sign(over_budget);
        assert_eq!(
            admit_state_runtime_package(&over_budget.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::UnsupportedRuntimeContract,
            "a valid signature cannot bypass the experimental publication ceiling"
        );
        assert_eq!(
            admit_runtime_package(&bytes).unwrap_err(),
            PackageAdmissionError::UnsupportedRuntimeContract
        );

        let released = runtime_package(RuntimeCapabilities::standard(), true);
        assert_eq!(
            admit_state_runtime_package(&released.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::UnsupportedRuntimeContract
        );
        assert!(admit_runtime_package(&released.encode().unwrap()).is_ok());

        // Changing only the signed declaration cannot silently downgrade the
        // same executable or transfer a signature between execution contracts.
        let mut downgraded = envelope;
        let PackageManifest::AgentRuntime(manifest) = &mut downgraded.manifest else {
            unreachable!()
        };
        manifest.contract = RuntimePackageContract::canonical();
        manifest.external_state_limits = None;
        assert_eq!(
            admit_runtime_package(&downgraded.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::Package(PackageError::InvalidSignature)
        );
        let signed_downgrade = sign(downgraded);
        assert_eq!(
            admit_runtime_package(&signed_downgrade.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidRuntimeProgram
        );
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn state_runtime_admission_does_not_expand_other_host_surfaces() {
        for program in [
            b"not a PVM".to_vec(),
            Assembler::new()
                .trap()
                .ecalli(crate::abi::hostcall::DEBUG_WRITE)
                .build_standard(),
            Assembler::new().trap().ecalli(0x181).build_standard(),
        ] {
            let envelope = state_runtime_envelope(program);
            assert_eq!(
                admit_state_runtime_package(&envelope.encode().unwrap()).unwrap_err(),
                PackageAdmissionError::InvalidRuntimeProgram
            );
        }
    }

    #[test]
    fn admits_exact_signed_actor_and_runtime_packages() {
        let actor_envelope = actor_package(ActorFixture::default());
        let actor_bytes = actor_envelope.encode().unwrap();
        let actor = admit_actor_package(&actor_bytes).unwrap();
        assert_eq!(actor.manifest().name, "fixture");
        assert_eq!(actor.exact_bytes(), actor_bytes);
        assert_eq!(*actor.package_ref(), BlobRef::of_bytes(&actor_bytes));
        assert_eq!(actor.deployment(), actor_envelope.deployment_id().unwrap());
        assert_eq!(actor.program(), ProgramId::of_pvm(actor.program_bytes()));
        assert_eq!(actor.producer(), actor.manifest().signing.producer);

        let runtime_envelope = runtime_package(RuntimeCapabilities::standard(), true);
        let runtime_bytes = runtime_envelope.encode().unwrap();
        let runtime = admit_runtime_package(&runtime_bytes).unwrap();
        assert_eq!(runtime.manifest().name, "fixture-runtime");
        assert_eq!(runtime.exact_bytes(), runtime_bytes);
        assert_eq!(*runtime.package_ref(), BlobRef::of_bytes(&runtime_bytes));
        assert_eq!(
            runtime.deployment(),
            runtime_envelope.deployment_id().unwrap()
        );
        assert_eq!(
            runtime.program(),
            ProgramId::of_pvm(runtime.program_bytes())
        );
        actor
            .require_runtime(AgentProfile::Local, &runtime)
            .unwrap();
    }

    #[test]
    #[ignore = "set CLERK_AGENT_PACKAGE to a canonical `vosx actor build` output"]
    fn canonical_clerk_agent_package_passes_host_admission() {
        let path = std::env::var_os("CLERK_AGENT_PACKAGE")
            .expect("CLERK_AGENT_PACKAGE must name the canonical signed VOS3 package");
        let bytes = std::fs::read(path).expect("read canonical Clerk Agent package");
        let admitted = admit_actor_package(&bytes).expect("host admits signed Clerk Agent package");
        assert_eq!(admitted.manifest().name, "clerk-ledger");
        assert_eq!(admitted.exact_bytes(), bytes);
        assert_eq!(
            admitted.manifest().requirements.lanes,
            LaneSet::of(StateLane::Linear)
        );
        assert_eq!(
            admitted.program(),
            ProgramId::of_pvm(admitted.program_bytes())
        );
        let policy = ActorMethodPolicyArtifact::decode(admitted.method_policy_bytes())
            .expect("signed Clerk method policy");
        let selector = |name| {
            policy
                .methods
                .iter()
                .find(|method| method.name == name)
                .expect("signed Clerk method")
                .authorization_policy
        };
        let vos_agent_sdk::method_policy::AuthorizationPolicySelector::ActorRole(operator) =
            selector("apply_transfer")
        else {
            panic!("transfer mutation must require the Operator role");
        };
        let vos_agent_sdk::method_policy::AuthorizationPolicySelector::ActorRole(member) =
            selector("account")
        else {
            panic!("account read must require the Member role");
        };
        assert_ne!(operator, member);
    }

    #[test]
    fn rejects_previous_generations_wrong_kinds_and_bad_signatures() {
        assert_eq!(
            admit_actor_package(b"VOSKprevious-generation").unwrap_err(),
            PackageAdmissionError::PreviousGeneration
        );

        let runtime = runtime_package(RuntimeCapabilities::standard(), true);
        assert_eq!(
            admit_actor_package(&runtime.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::WrongKind
        );
        let actor = actor_package(ActorFixture::default());
        assert_eq!(
            admit_runtime_package(&actor.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::WrongKind
        );

        let mut tampered = actor;
        tampered.manifest.signing_mut().signature[0] ^= 0xff;
        assert_eq!(
            admit_actor_package(&tampered.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::Package(PackageError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_nonstandard_actor_task_and_runtime_programs() {
        let actor = actor_package(ActorFixture {
            valid_actor_pvm: false,
            ..ActorFixture::default()
        });
        assert_eq!(
            admit_actor_package(&actor.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidActorProgram
        );

        let actor = actor_package(ActorFixture {
            task: Some(TaskProofRequirement::None),
            valid_task_pvm: false,
            ..ActorFixture::default()
        });
        assert!(matches!(
            admit_actor_package(&actor.encode().unwrap()),
            Err(PackageAdmissionError::InvalidTaskProgram(_))
        ));

        let runtime = runtime_package(RuntimeCapabilities::standard(), false);
        assert_eq!(
            admit_runtime_package(&runtime.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidRuntimeProgram
        );
    }

    #[test]
    fn runtime_admission_rejects_retired_and_non_outer_program_surfaces() {
        let mut legacy = Assembler::new();
        legacy.trap();
        let jar = runtime_package_with_program(RuntimeCapabilities::standard(), legacy.build());
        assert_eq!(
            admit_runtime_package(&jar.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidRuntimeProgram,
            "a signed VOS3 envelope must not revive a JAR-generation outer program"
        );

        let mut vos_only = Assembler::new();
        let vos_only = vos_only
            .trap()
            .ecalli(crate::abi::hostcall::DEBUG_WRITE)
            .build_standard();
        let runtime = runtime_package_with_program(RuntimeCapabilities::standard(), vos_only);
        assert_eq!(
            admit_runtime_package(&runtime.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidRuntimeProgram,
            "even an unreachable VOS-only host call is outside the outer Refine interface"
        );

        // The same `ecalli` is valid inside an AgentActor: inner-machine host
        // exits are consumed by the outer runtime and are not the outer
        // runtime's own host surface.
        let mut actor = actor_package(ActorFixture::default());
        let mut inner = Assembler::new();
        let inner = inner
            .ecalli(crate::abi::hostcall::DEBUG_WRITE)
            .trap()
            .build_standard();
        let PackageManifest::Actor(manifest) = &mut actor.manifest else {
            unreachable!()
        };
        let previous = manifest.program.clone();
        manifest.program = BlobRef::of_bytes(&inner);
        let stored = actor
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.identity == previous)
            .unwrap();
        *stored = artifact(&inner);
        actor
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        let actor = sign(actor);
        admit_actor_package(&actor.encode().unwrap())
            .expect("standard inner actor host exits remain admissible");
    }

    #[test]
    fn enforces_profile_and_runtime_capability_compatibility() {
        let linear = admit_actor(ActorFixture {
            lane: Some(StateLane::Linear),
            ..ActorFixture::default()
        });
        let standard = admit_runtime(RuntimeCapabilities::standard());
        assert_eq!(
            linear.require_runtime(AgentProfile::Private, &standard),
            Err(PackageAdmissionError::UnsupportedProfile)
        );
        assert!(
            linear
                .require_runtime(AgentProfile::Shared, &standard)
                .is_ok()
        );

        let no_lanes = admit_runtime(RuntimeCapabilities {
            lanes: LaneSet::NONE,
            ..RuntimeCapabilities::standard()
        });
        assert_eq!(
            linear.require_runtime(AgentProfile::Local, &no_lanes),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );

        let scheduled = admit_actor(ActorFixture {
            scheduling: true,
            ..ActorFixture::default()
        });
        assert_eq!(
            scheduled.require_runtime(AgentProfile::Local, &standard),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );
        let scheduler = admit_runtime(RuntimeCapabilities {
            scheduling: true,
            ..RuntimeCapabilities::standard()
        });
        assert!(
            scheduled
                .require_runtime(AgentProfile::Local, &scheduler)
                .is_ok()
        );

        let proof_system = Hash::digest(b"test/proof-system", &[b"v1"]);
        let proof_actor = admit_actor(ActorFixture {
            task: Some(TaskProofRequirement::Required { proof_system }),
            ..ActorFixture::default()
        });
        assert_eq!(
            proof_actor.require_runtime(AgentProfile::Local, &standard),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );
        let mut proof_systems = ProofSystemSet::EMPTY;
        proof_systems.insert(proof_system).unwrap();
        let proof_runtime = admit_runtime(RuntimeCapabilities {
            proof_systems,
            ..RuntimeCapabilities::standard()
        });
        assert!(
            proof_actor
                .require_runtime(AgentProfile::Local, &proof_runtime)
                .is_ok()
        );
    }
}
