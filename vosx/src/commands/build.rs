//! Build canonical actor PVMs and signed `.vos` packages.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use vos::agent::sdk;
use vos::agent::sdk::wire::CanonicalWire;

const RUSTC_WRAPPER_MODE: &str = "VOSX_CANONICAL_RUSTC_WRAPPER";
const RUSTC_WRAPPER_SOURCE_ROOT: &str = "VOSX_CANONICAL_SOURCE_ROOT";
const RUSTC_WRAPPER_TARGET_ROOT: &str = "VOSX_CANONICAL_TARGET_ROOT";
const RUSTC_UNIT_METADATA_DOMAIN: &[u8] = b"vos/rustc-unit-metadata/actor";
// Canonical actor identities must not depend on the mutable nightly alias.
const CANONICAL_GUEST_TOOLCHAIN: &str = "+nightly-2026-03-20";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RustcUnitIdentity {
    package_name: OsString,
    package_version: OsString,
    package_repository: OsString,
    manifest_dir: Option<PathBuf>,
}

impl RustcUnitIdentity {
    fn from_environment() -> Self {
        Self {
            package_name: std::env::var_os("CARGO_PKG_NAME").unwrap_or_default(),
            package_version: std::env::var_os("CARGO_PKG_VERSION").unwrap_or_default(),
            package_repository: std::env::var_os("CARGO_PKG_REPOSITORY").unwrap_or_default(),
            manifest_dir: std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from),
        }
    }
}

pub struct Args {
    pub program: PathBuf,
    pub name: Option<String>,
    pub out_dir: PathBuf,
    /// Optional prebuilt AMP2 bytes. Actor builds accept them only when they
    /// byte-equal the artifact generated from authenticated macro metadata.
    pub method_policy: Option<PathBuf>,
    pub schemas: Option<PathBuf>,
    pub agent_schema: Option<PathBuf>,
    pub agent_authorizations: Option<PathBuf>,
    pub tasks: Vec<PathBuf>,
    pub crdt: bool,
    pub scheduling: bool,
    pub proof_system: Option<sdk::Hash>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let keypair = crate::identity::load_or_create()?;
    run_with_signer(args, &keypair)
}

pub(super) fn run_with_signer(
    args: Args,
    keypair: &libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    if args.tasks.len() > sdk::task::MAX_TASK_DEPENDENCIES {
        bail!(
            "actor package has {} Task dependencies; the canonical maximum is {}",
            args.tasks.len(),
            sdk::task::MAX_TASK_DEPENDENCIES,
        );
    }

    let program = resolve_program_input(&args.program)?;
    let input = std::fs::read(&program).with_context(|| format!("read {}", program.display()))?;
    let is_pvm = program.extension().and_then(|extension| extension.to_str()) == Some("pvm");
    let actor_pvm = if is_pvm {
        input.clone()
    } else {
        vos_pvm_compiler::link_elf_spi(&input)
            .map_err(|error| anyhow!("transpile {}: {error:?}", program.display()))?
    };
    if actor_pvm.is_empty() || vos_pvm::spi::parse_standard_program(&actor_pvm).is_none() {
        bail!("{} is not a canonical standard PVM", program.display());
    }

    let embedded_metadata =
        (!is_pvm).then(|| vos::metadata::raw_section_from_elf(&input).unwrap_or_default());
    let metadata_bytes = exact_producer_input(
        args.schemas.as_deref(),
        embedded_metadata,
        ".vos_meta actor metadata",
        "--metadata",
        &program,
    )?;
    let actor_metadata = vos::metadata::decode(&metadata_bytes).ok_or_else(|| {
        anyhow!(
            "{} has no valid authenticated actor metadata",
            program.display()
        )
    })?;

    let embedded_schema = (!is_pvm).then(|| {
        vos::metadata::raw_named_section_from_elf(&input, b".vos_agent").unwrap_or_default()
    });
    let actor_schema_bytes = exact_producer_input(
        args.agent_schema.as_deref(),
        embedded_schema,
        ".vos_agent AAS2 schema",
        "--agent-schema",
        &program,
    )?;
    let actor_schema = sdk::schema::decode(&actor_schema_bytes).map_err(|error| {
        anyhow!(
            "{} has no canonical AAS2 AgentActor schema: {error}",
            program.display()
        )
    })?;

    let embedded_authorizations = (!is_pvm)
        .then(|| vos::metadata::raw_agent_authorizations_from_elf(&input).unwrap_or_default());
    let authorization_bytes = exact_producer_input(
        args.agent_authorizations.as_deref(),
        embedded_authorizations,
        ".vos_agent_auth authorization metadata",
        "--agent-authorizations",
        &program,
    )?;
    let authorizations = vos::metadata::decode_agent_authorizations(&authorization_bytes)
        .ok_or_else(|| {
            anyhow!(
                "{} has no canonical AAM1 Agent authorization metadata",
                program.display()
            )
        })?;

    validate_agent_metadata_surface(&actor_metadata, &actor_schema, &authorizations)?;
    validate_constructor_metadata(&actor_metadata, &actor_schema)?;
    if args.crdt && actor_schema.lanes() != sdk::LaneSet::of(sdk::StateLane::Merge) {
        bail!(
            "{} is not a merge-only actor; field types derive lanes and --crdt cannot override them",
            program.display(),
        );
    }

    let method_uses_proof = actor_metadata.messages.iter().any(|method| method.attested);
    let mut task_dependencies = args
        .tasks
        .iter()
        .map(|input| build_actor_task_dependency(input, args.proof_system))
        .collect::<anyhow::Result<Vec<_>>>()?;
    task_dependencies.sort_unstable_by_key(|dependency| dependency.dependency.task);
    if task_dependencies
        .windows(2)
        .any(|pair| pair[0].dependency.task == pair[1].dependency.task)
    {
        bail!("duplicate canonical Task dependency");
    }
    let task_uses_proof = task_dependencies
        .iter()
        .any(|dependency| dependency.provable);
    match (method_uses_proof || task_uses_proof, args.proof_system) {
        (true, None) => {
            bail!("attested methods and provable Task dependencies require an exact --proof-system")
        }
        (false, Some(_)) => {
            bail!("--proof-system was supplied but no attested method or provable Task uses it")
        }
        _ => {}
    }

    let schema_reference = sdk::BlobRef::of_bytes(&actor_schema_bytes);
    let mut methods = Vec::with_capacity(actor_metadata.messages.len());
    let mut introspection_methods = Vec::with_capacity(actor_metadata.messages.len());
    for ((metadata, schema_method), authorization) in actor_metadata
        .messages
        .iter()
        .zip(&actor_schema.methods)
        .zip(&authorizations)
    {
        let authorization_policy = match &authorization.selector {
            vos::metadata::ParsedAgentAuthorizationSelector::Public => {
                sdk::method_policy::AuthorizationPolicySelector::Public
            }
            vos::metadata::ParsedAgentAuthorizationSelector::SpaceRole(identity) => {
                sdk::method_policy::AuthorizationPolicySelector::SpaceRole(sdk::RoleId(*identity))
            }
            vos::metadata::ParsedAgentAuthorizationSelector::ActorRole(identity) => {
                sdk::method_policy::AuthorizationPolicySelector::ActorRole(sdk::RoleId(*identity))
            }
            vos::metadata::ParsedAgentAuthorizationSelector::Capability(name) => {
                sdk::method_policy::AuthorizationPolicySelector::Capability(
                    sdk::CapabilityId::named(name),
                )
            }
        };
        let attestation = if metadata.attested {
            sdk::method_policy::AttestationRequirement::Required {
                proof_system: args
                    .proof_system
                    .expect("proof-system presence was validated"),
            }
        } else {
            sdk::method_policy::AttestationRequirement::None
        };
        methods.push(sdk::method_policy::ActorMethodPolicy {
            name: metadata.name.clone(),
            mode: schema_method.mode,
            arguments: metadata
                .fields
                .iter()
                .map(|field| sdk::method_policy::MethodArgument {
                    name: field.name.clone(),
                    type_identity: field.ty.clone(),
                })
                .collect(),
            return_type_identity: metadata.returns.clone(),
            authorization_policy,
            idempotency: sdk::method_policy::IdempotencyRequirement::for_mode(schema_method.mode),
            attestation,
        });
        introspection_methods.push(sdk::introspection::ActorMethodIntrospection {
            name: metadata.name.clone(),
            doc: metadata.doc.clone(),
            cli_exposure: if metadata.exposed_to_cli {
                sdk::introspection::CliExposure::Exposed
            } else {
                sdk::introspection::CliExposure::Hidden
            },
            timeout_ms: metadata.timeout_ms,
            dispatch: match metadata.mode {
                0 => sdk::introspection::MethodDispatch::Sync,
                1 => sdk::introspection::MethodDispatch::Job,
                value => bail!(
                    "method '{}' has unknown dispatch mode {value}",
                    metadata.name
                ),
            },
        });
    }
    methods.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    introspection_methods.sort_unstable_by(|left, right| left.name.cmp(&right.name));

    let method_policy = sdk::method_policy::ActorMethodPolicyArtifact {
        actor_schema: schema_reference.clone(),
        methods,
    };
    method_policy
        .validate_against_schema_bytes(&actor_schema_bytes)
        .map_err(|error| anyhow!("generated AMP2 method policy is invalid: {error}"))?;
    let method_policy_bytes = method_policy.encode()?;
    if let Some(path) = args.method_policy.as_deref() {
        let supplied = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if supplied != method_policy_bytes {
            bail!(
                "{} does not byte-equal the canonical AMP2 generated from actor metadata",
                path.display()
            );
        }
    }
    let method_policy_reference = sdk::BlobRef::of_bytes(&method_policy_bytes);
    let introspection = sdk::introspection::ActorIntrospectionArtifact {
        actor_schema: schema_reference.clone(),
        method_policy: method_policy_reference.clone(),
        actor_doc: actor_metadata.doc.clone(),
        methods: introspection_methods,
    };
    introspection
        .validate_against_artifact_bytes(&actor_schema_bytes, &method_policy_bytes)
        .map_err(|error| anyhow!("generated AAI1 introspection is invalid: {error}"))?;
    let introspection_bytes = introspection.encode()?;
    let introspection_reference = sdk::BlobRef::of_bytes(&introspection_bytes);

    let task_set = sdk::task::TaskDependencySetArtifact {
        dependencies: task_dependencies
            .iter()
            .map(|dependency| dependency.dependency.clone())
            .collect(),
    };
    task_set.validate()?;
    let task_set_bytes = task_set.encode()?;
    let task_set_reference = sdk::BlobRef::of_bytes(&task_set_bytes);
    let proof_systems = method_policy
        .proof_systems()?
        .union(&task_set.proof_systems()?)?;
    let requirements = sdk::RuntimeRequirements {
        lanes: actor_schema.lanes(),
        scheduling: args.scheduling,
        proof_systems,
    };

    let public_key = raw_ed25519_public_key(keypair)?;
    let producer = sdk::ProducerId::of_public_key(&public_key);
    let actor_program = sdk::ProgramId::of_pvm(&actor_pvm);
    let mut artifacts = vec![
        package_artifact(actor_pvm.clone()),
        package_artifact(actor_schema_bytes),
        package_artifact(method_policy_bytes),
        package_artifact(introspection_bytes),
        package_artifact(task_set_bytes),
    ];
    artifacts.extend(
        task_dependencies
            .iter()
            .map(|dependency| package_artifact(dependency.pvm.clone())),
    );
    artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));

    // Above the standard actor profile the package declares what its
    // program encodes, so a large actor is a signed, visible choice that the
    // installing owner admits against its own ceilings.
    let resources = if actor_pvm.len() > sdk::STANDARD_ACTOR_PROGRAM_BYTES {
        if actor_pvm.len() > sdk::MAX_RUNTIME_PROGRAM_BYTES {
            bail!(
                "actor program is {} B; the runtime maximum is {} B",
                actor_pvm.len(),
                sdk::MAX_RUNTIME_PROGRAM_BYTES,
            );
        }
        Some(
            vos::agent::package_admission::actor_program_resources(&actor_pvm)
                .ok_or_else(|| anyhow!("actor program is not a standard PVM"))?,
        )
    } else {
        None
    };
    let name = args.name.unwrap_or(actor_metadata.actor_name);
    let mut package = sdk::package::PackageEnvelope {
        manifest: sdk::package::PackageManifest::Actor(sdk::package::ActorPackageManifest {
            name: name.clone(),
            program: sdk::BlobRef::of_bytes(&actor_pvm),
            contract: sdk::contract::ActorPackageContract::canonical(),
            state_lane_schema: schema_reference,
            method_policy: method_policy_reference,
            introspection: introspection_reference,
            task_dependencies: task_set_reference,
            scheduling: args.scheduling,
            requirements,
            resources,
            signing: sdk::package::PackageSigning {
                producer,
                public_key,
                signature: [0; sdk::package::PACKAGE_SIGNATURE_BYTES],
            },
        }),
        artifacts,
    };
    let signature = sign_ed25519_exact(keypair, &package.signing_bytes()?)?;
    package.manifest.signing_mut().signature = signature;
    package.validate_shape()?;
    let deployment_id = package.deployment_id()?;
    let package_bytes = package.encode()?;

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;
    let pvm_path = args.out_dir.join(format!("{name}.pvm"));
    let package_path = args.out_dir.join(format!("{name}.vos"));
    std::fs::write(&pvm_path, actor_pvm)
        .with_context(|| format!("write {}", pvm_path.display()))?;
    std::fs::write(&package_path, package_bytes)
        .with_context(|| format!("write {}", package_path.display()))?;

    println!("built {}", package_path.display());
    println!("  actor_pvm      = {}", pvm_path.display());
    println!("  program_id     = {}", hex::encode(actor_program.0));
    println!("  deployment_id  = {}", hex::encode(deployment_id.0));
    for (index, dependency) in task_dependencies.iter().enumerate() {
        println!(
            "  task[{index}]        = {}",
            hex::encode(dependency.dependency.task.0)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct ActorTaskDependencyBuild {
    dependency: sdk::task::TaskDependency,
    pvm: Vec<u8>,
    provable: bool,
}

fn exact_producer_input(
    supplied: Option<&Path>,
    embedded: Option<Vec<u8>>,
    description: &str,
    option: &str,
    program: &Path,
) -> anyhow::Result<Vec<u8>> {
    match supplied {
        Some(path) => {
            let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            if embedded.as_ref().is_some_and(|value| *value != bytes) {
                bail!(
                    "{} does not match {} embedded in {}",
                    path.display(),
                    description,
                    program.display(),
                );
            }
            Ok(bytes)
        }
        None => embedded.filter(|bytes| !bytes.is_empty()).ok_or_else(|| {
            anyhow!(
                "{} has no {description}; pass {option} with its exact bytes",
                program.display()
            )
        }),
    }
}

fn validate_agent_metadata_surface(
    metadata: &vos::metadata::ParsedMeta,
    schema: &sdk::schema::ParsedSchema,
    authorizations: &[vos::metadata::ParsedAgentMethodAuthorization],
) -> anyhow::Result<()> {
    if metadata.messages.len() != schema.methods.len()
        || metadata.messages.len() != authorizations.len()
    {
        bail!("actor metadata, AAS2, and authorization method counts differ");
    }
    for ((metadata, schema), authorization) in metadata
        .messages
        .iter()
        .zip(&schema.methods)
        .zip(authorizations)
    {
        if metadata.name != schema.name || metadata.name != authorization.name {
            bail!(
                "actor metadata surfaces differ at method '{}'",
                metadata.name
            );
        }
        if metadata.is_query != schema.mode.write_lane().is_none() {
            bail!(
                "method '{}' query/mutation metadata disagrees",
                metadata.name
            );
        }
        let selector_count = usize::from(metadata.space_role.is_some())
            + usize::from(metadata.actor_role.is_some())
            + usize::from(metadata.capability.is_some());
        if selector_count > 1 {
            bail!(
                "method '{}' declares multiple authorization selectors",
                metadata.name
            );
        }
        let selector_matches = match (
            metadata.space_role,
            metadata.actor_role,
            metadata.capability.as_deref(),
            &authorization.selector,
        ) {
            (None, None, None, vos::metadata::ParsedAgentAuthorizationSelector::Public)
            | (
                Some(_),
                None,
                None,
                vos::metadata::ParsedAgentAuthorizationSelector::SpaceRole(_),
            )
            | (
                None,
                Some(_),
                None,
                vos::metadata::ParsedAgentAuthorizationSelector::ActorRole(_),
            ) => true,
            (
                None,
                None,
                Some(expected),
                vos::metadata::ParsedAgentAuthorizationSelector::Capability(actual),
            ) => expected == actual,
            _ => false,
        };
        if !selector_matches {
            bail!(
                "method '{}' legacy selector kind disagrees with exact AAM1 authorization",
                metadata.name
            );
        }
    }
    Ok(())
}

fn validate_constructor_metadata(
    metadata: &vos::metadata::ParsedMeta,
    schema: &sdk::schema::ParsedSchema,
) -> anyhow::Result<()> {
    let matches = match &schema.constructor {
        sdk::schema::ConstructorContract::Forbidden => metadata.constructor.is_empty(),
        sdk::schema::ConstructorContract::RequiredRaw(argument) => {
            metadata.constructor.len() == 1
                && metadata.constructor[0].name == argument.name
                && metadata.constructor[0].ty == sdk::schema::RAW_CONSTRUCTOR_TYPE_IDENTITY
                && argument.type_identity == sdk::schema::RAW_CONSTRUCTOR_TYPE_IDENTITY
        }
        sdk::schema::ConstructorContract::RequiredNamed(arguments) => {
            arguments.len() == metadata.constructor.len()
                && arguments
                    .iter()
                    .zip(&metadata.constructor)
                    .all(|(schema, metadata)| {
                        schema.name == metadata.name
                            && schema
                                .type_identity
                                // AAS2 uses stringify!, while .vos_meta uses
                                // the macro's whitespace-free ty_string.
                                .replace(' ', "")
                                .strip_suffix(&metadata.ty)
                                .is_some_and(|prefix| prefix.ends_with("::"))
                    })
        }
    };
    if !matches {
        bail!(".vos_meta constructor ABI does not match the exact AAS2 constructor contract");
    }
    Ok(())
}

fn package_artifact(bytes: Vec<u8>) -> sdk::package::PackageArtifact {
    sdk::package::PackageArtifact {
        identity: sdk::BlobRef::of_bytes(&bytes),
        bytes,
    }
}

fn raw_ed25519_public_key(keypair: &libp2p::identity::Keypair) -> anyhow::Result<[u8; 32]> {
    if keypair.key_type() != libp2p::identity::KeyType::Ed25519 {
        bail!("Actor VOS3 packages require an Ed25519 operator identity");
    }
    Ok(keypair
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("operator identity did not yield a raw Ed25519 public key"))?
        .to_bytes())
}

fn sign_ed25519_exact(
    keypair: &libp2p::identity::Keypair,
    message: &[u8],
) -> anyhow::Result<[u8; 64]> {
    if keypair.key_type() != libp2p::identity::KeyType::Ed25519 {
        bail!("Actor VOS3 packages require an Ed25519 operator identity");
    }
    keypair
        .sign(message)
        .map_err(|error| anyhow!("sign Actor deployment: {error}"))?
        .try_into()
        .map_err(|signature: Vec<u8>| {
            anyhow!(
                "Ed25519 operator returned a {}-byte signature instead of 64 bytes",
                signature.len()
            )
        })
}

fn build_actor_task_dependency(
    input: &Path,
    proof_system: Option<sdk::Hash>,
) -> anyhow::Result<ActorTaskDependencyBuild> {
    let program = resolve_task_input(input)?;
    if program.extension().and_then(|extension| extension.to_str()) == Some("pvm") {
        bail!(
            "{} is a PVM without authenticated witness-layout metadata; pass the canonical Task ELF or project directory",
            program.display()
        );
    }
    let elf = std::fs::read(&program).with_context(|| format!("read {}", program.display()))?;
    let execution_schema = vos::agent::schema::raw_section_from_elf(&elf).unwrap_or_default();
    require_execution_entry(
        &execution_schema,
        vos::agent::schema::ExecutionEntryKind::Task,
        &program,
    )?;
    let metadata = vos::metadata::from_elf(&elf)
        .ok_or_else(|| anyhow!("{} has no canonical Task metadata", program.display()))?;
    let pvm = vos_pvm_compiler::link_elf_spi(&elf)
        .map_err(|error| anyhow!("transpile Task {}: {error:?}", program.display()))?;
    if pvm.is_empty() || vos_pvm::spi::parse_standard_program(&pvm).is_none() {
        bail!(
            "{} did not produce a canonical standard Task PVM",
            program.display()
        );
    }
    let (witness_address, witness_capacity) = vos::zk::witness_symbol(&elf).ok_or_else(|| {
        anyhow!(
            "{} does not export the required __VOS_WITNESS buffer",
            program.display()
        )
    })?;
    let witness_address = u32::try_from(witness_address)
        .context("Task witness address does not fit the PVM address space")?;
    let witness_capacity = u32::try_from(witness_capacity)
        .context("Task witness capacity does not fit the package wire")?;
    let proof = if metadata.provable {
        sdk::task::TaskProofRequirement::Required {
            proof_system: proof_system.ok_or_else(|| {
                anyhow!(
                    "provable Task {} requires an exact --proof-system",
                    program.display()
                )
            })?,
        }
    } else {
        sdk::task::TaskProofRequirement::None
    };
    let dependency = sdk::task::TaskDependency::new(
        sdk::BlobRef::of_bytes(&pvm),
        sdk::ProgramId::of_pvm(&pvm),
        witness_address,
        witness_capacity,
        proof,
    )?;
    Ok(ActorTaskDependencyBuild {
        dependency,
        pvm,
        provable: metadata.provable,
    })
}

fn require_execution_entry(
    schema: &[u8],
    expected: vos::agent::schema::ExecutionEntryKind,
    program: &Path,
) -> anyhow::Result<vos::agent::schema::ParsedSchema> {
    let parsed = vos::agent::schema::decode(schema).ok_or_else(|| {
        anyhow!(
            "{} has no valid authenticated execution schema",
            program.display()
        )
    })?;
    if parsed.entry != expected {
        bail!(
            "{} was compiled for {:?}, but this build requires {:?}",
            program.display(),
            parsed.entry,
            expected,
        );
    }
    Ok(parsed)
}

/// Resolve a Task input without routing it through the actor-only
/// `cargo actor` subcommand. Tasks are ordinary binary crates for the pinned
/// PVM target, so Cargo's JSON artifact stream is the authority for the ELF
/// location (including custom target-directory configuration).
fn resolve_task_input(input: &Path) -> anyhow::Result<PathBuf> {
    if !input.is_dir() {
        return Ok(input.to_path_buf());
    }
    let project = std::fs::canonicalize(input)
        .with_context(|| format!("resolve Task project {}", input.display()))?;
    let manifest_path = project.join("Cargo.toml");
    if !manifest_path.is_file() {
        bail!("Task project {} has no Cargo.toml", project.display());
    }
    let build_root = std::fs::canonicalize(actor_build_root(&project)?)
        .with_context(|| format!("resolve Task build root for {}", input.display()))?;
    let source_root = canonical_source_root(&build_root);
    // Own a source-root-relative target directory just as actor packaging
    // does. Cargo's output path is part of rustc's invocation; inheriting an
    // arbitrary CARGO_TARGET_DIR would otherwise perturb crate metadata and
    // the linked Task identity even though JSON discovery found the right ELF.
    let target_dir = canonical_target_dir(&build_root)?;
    let mut command = Command::new("cargo");
    command
        .args([
            CANONICAL_GUEST_TOOLCHAIN,
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
            "--manifest-path",
        ])
        .arg(&manifest_path)
        .current_dir(&build_root)
        .env("RUSTC_WRAPPER", std::env::current_exe()?)
        .env(RUSTC_WRAPPER_MODE, "1")
        .env(RUSTC_WRAPPER_SOURCE_ROOT, source_root)
        .env(RUSTC_WRAPPER_TARGET_ROOT, &target_dir)
        .env("CARGO_TARGET_DIR", target_dir);
    let output = command
        .output()
        .with_context(|| format!("run `cargo +nightly build` in {}", build_root.display()))?;
    if !output.status.success() {
        bail!(
            "Task build failed in {} with status {}:\n{}",
            input.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut artifacts = Vec::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(artifact_manifest) = message
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
        else {
            continue;
        };
        if std::fs::canonicalize(&artifact_manifest).ok() != Some(manifest_path.clone()) {
            continue;
        }
        let is_binary = message
            .get("target")
            .and_then(|target| target.get("kind"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")));
        if !is_binary {
            continue;
        }
        let elf = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|path| path.extension().and_then(OsStr::to_str) == Some("elf"))
            .or_else(|| {
                message
                    .get("filenames")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .find(|path| path.extension().and_then(OsStr::to_str) == Some("elf"))
            });
        if let Some(elf) = elf {
            artifacts.push(elf);
        }
    }
    artifacts.sort();
    artifacts.dedup();
    match artifacts.as_slice() {
        [elf] if elf.is_file() => Ok(elf.clone()),
        [] => bail!(
            "Task build succeeded but Cargo reported no binary ELF for {}; ensure the Task is a binary crate using the VOS PVM target",
            manifest_path.display()
        ),
        _ => bail!(
            "Task project {} produced multiple binary ELFs; pass one ELF explicitly",
            project.display()
        ),
    }
}

fn resolve_program_input(input: &Path) -> anyhow::Result<PathBuf> {
    if !input.is_dir() {
        return Ok(input.to_path_buf());
    }
    let project = std::fs::canonicalize(input)
        .with_context(|| format!("resolve actor project {}", input.display()))?;
    let manifest_path = project.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read actor manifest {}", manifest_path.display()))?;
    let (package_name, actor_target_name) = actor_names_from_manifest(&manifest)?;
    let build_root = std::fs::canonicalize(actor_build_root(&project)?)
        .with_context(|| format!("resolve actor build root for {}", input.display()))?;
    let source_root = canonical_source_root(&build_root);
    // Own an isolated canonical artifact location. Reusing the ordinary
    // actor target can make Cargo accept an ELF compiled without this rustc
    // wrapper, so the supposedly canonical ProgramId then depends on the
    // checkout path of the preceding `cargo actor` invocation.
    let target_dir = canonical_target_dir(&build_root)?;
    let mut command = Command::new("cargo");
    command.args([CANONICAL_GUEST_TOOLCHAIN, "actor"]);
    if build_root != project {
        command.args(["-p", &package_name]);
    }
    command
        .env("RUSTC_WRAPPER", std::env::current_exe()?)
        .env(RUSTC_WRAPPER_MODE, "1")
        .env(RUSTC_WRAPPER_SOURCE_ROOT, source_root)
        .env(RUSTC_WRAPPER_TARGET_ROOT, &target_dir)
        .env("CARGO_TARGET_DIR", &target_dir);
    let status = command
        .current_dir(&build_root)
        .status()
        .with_context(|| format!("run `cargo +nightly actor` in {}", build_root.display()))?;
    if !status.success() {
        bail!(
            "actor build failed in {} with status {status}",
            input.display()
        );
    }
    let elf = target_dir
        .join("riscv64em-vos/release")
        .join(format!("{actor_target_name}.elf"));
    if !elf.is_file() {
        bail!(
            "actor build succeeded but did not produce {}; ensure the project uses the VOS cargo actor configuration",
            elf.display()
        );
    }
    Ok(elf)
}

fn canonical_source_root(build_root: &Path) -> &Path {
    build_root
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .unwrap_or(build_root)
}

/// Isolate canonical Cargo output by every input Cargo does not fingerprint
/// for a rustc wrapper. Cargo keys a wrapper by its path, so rebuilding `vosx`
/// in place would otherwise allow artifacts produced by an older wrapper to
/// survive indefinitely. Source files remain ordinary Cargo inputs; this
/// namespace covers the wrapper, toolchain, and platform contract.
fn canonical_target_dir(build_root: &Path) -> anyhow::Result<PathBuf> {
    let wrapper = std::env::current_exe().context("locate the canonical rustc wrapper")?;
    let wrapper_bytes = std::fs::read(&wrapper)
        .with_context(|| format!("read canonical rustc wrapper {}", wrapper.display()))?;
    let toolchain = Command::new("rustc")
        .args([CANONICAL_GUEST_TOOLCHAIN, "--version", "--verbose"])
        .output()
        .context("query the canonical nightly rustc identity")?;
    if !toolchain.status.success() {
        bail!(
            "query canonical nightly rustc identity: {}",
            String::from_utf8_lossy(&toolchain.stderr)
        );
    }
    let source_root = canonical_source_root(build_root)
        .as_os_str()
        .as_encoded_bytes();
    let identity = vos::service::Hash::digest(
        b"vos/canonical-cargo-cache",
        &[
            &wrapper_bytes,
            &toolchain.stdout,
            &vos::service::PLATFORM_ID.0,
            &vos::service::EXECUTION_SEMANTICS_ID.0,
            source_root,
        ],
    );
    Ok(build_root
        .join("target/vosx-canonical")
        .join(hex::encode(identity.0)))
}

/// Cargo invokes the current `vosx` executable as a rustc wrapper while
/// compiling canonical actors. Cargo's generated `-Cmetadata` includes local
/// source paths before rustc sees remapping flags, so merely remapping paths is
/// insufficient: identical worktrees can still produce different code and
/// `ProgramId`s. Strip that generated value, install a protocol-stable one,
/// and remap the complete source repository rather than only the actor member.
pub fn maybe_run_canonical_rustc_wrapper() {
    if std::env::var_os(RUSTC_WRAPPER_MODE).is_none() {
        return;
    }
    let mut arguments = std::env::args_os().skip(1);
    let Some(rustc) = arguments.next() else {
        eprintln!("vosx canonical rustc wrapper: missing rustc executable");
        std::process::exit(1);
    };
    let Some(source_root) = std::env::var_os(RUSTC_WRAPPER_SOURCE_ROOT) else {
        eprintln!("vosx canonical rustc wrapper: missing source root");
        std::process::exit(1);
    };
    let Some(target_root) = std::env::var_os(RUSTC_WRAPPER_TARGET_ROOT) else {
        eprintln!("vosx canonical rustc wrapper: missing target root");
        std::process::exit(1);
    };
    let arguments = arguments.collect::<Vec<_>>();
    let unit = RustcUnitIdentity::from_environment();
    let status = Command::new(rustc)
        .args(canonical_rustc_arguments(
            arguments,
            &source_root,
            &target_root,
            &unit,
        ))
        .status();
    match status {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("vosx canonical rustc wrapper: {error}");
            std::process::exit(1);
        }
    }
}

fn canonical_rustc_arguments(
    arguments: impl IntoIterator<Item = OsString>,
    source_root: &OsStr,
    target_root: &OsStr,
    unit: &RustcUnitIdentity,
) -> Vec<OsString> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let metadata = canonical_rustc_unit_metadata(&arguments, source_root, target_root, unit);
    let mut arguments = arguments.into_iter().peekable();
    let mut canonical = Vec::new();
    while let Some(argument) = arguments.next() {
        if argument == "-C"
            && arguments
                .peek()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with("metadata="))
        {
            arguments.next();
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|value| value.starts_with("-Cmetadata="))
        {
            continue;
        }
        canonical.push(argument);
    }
    canonical.push(OsString::from(format!("-Cmetadata={metadata}")));
    let mut remap = OsString::from("--remap-path-prefix=");
    remap.push(source_root);
    remap.push("=vos-source");
    canonical.push(remap);
    let mut remap = OsString::from("--remap-path-prefix=");
    remap.push(target_root);
    remap.push("=vos-target");
    canonical.push(remap);
    canonical
}

/// Derive rustc's crate disambiguator from stable Cargo-unit inputs.
///
/// Cargo's own metadata contains absolute path-package identities, so it
/// cannot be used verbatim for canonical builds. A single replacement for
/// every crate is also invalid: two versions or sources of the same crate
/// would receive the same StableCrateId. This digest keeps the unit identity
/// while normalizing checkout- and Cargo-home-dependent paths.
fn canonical_rustc_unit_metadata(
    arguments: &[OsString],
    source_root: &OsStr,
    target_root: &OsStr,
    unit: &RustcUnitIdentity,
) -> String {
    let source_root = Path::new(source_root);
    let mut identity = Vec::new();
    push_metadata_part(
        &mut identity,
        b"package-name",
        unit.package_name.as_os_str(),
    );
    push_metadata_part(
        &mut identity,
        b"package-version",
        unit.package_version.as_os_str(),
    );
    push_metadata_part(
        &mut identity,
        b"package-repository",
        unit.package_repository.as_os_str(),
    );
    let package_source = unit
        .manifest_dir
        .as_deref()
        .map(|manifest_dir| canonical_package_source(manifest_dir, source_root))
        .unwrap_or_else(|| OsString::from("cargo-package-unknown"));
    push_metadata_part(&mut identity, b"package-source", &package_source);

    let mut arguments = arguments.iter().peekable();
    while let Some(argument) = arguments.next() {
        if argument == "-C"
            && arguments
                .peek()
                .and_then(|value| value.to_str())
                .is_some_and(|value| {
                    value.starts_with("metadata=") || value.starts_with("extra-filename=")
                })
        {
            arguments.next();
            continue;
        }
        if argument.to_str().is_some_and(|value| {
            value.starts_with("-Cmetadata=") || value.starts_with("-Cextra-filename=")
        }) {
            continue;
        }
        if argument == "--extern" {
            if let Some(extern_crate) = arguments.next() {
                let extern_crate = extern_crate.to_string_lossy();
                let name = extern_crate
                    .split_once('=')
                    .map_or(extern_crate.as_ref(), |(name, _)| name);
                push_metadata_part(&mut identity, b"rustc-extern", OsStr::new(name));
            }
            continue;
        }
        if let Some(extern_crate) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--extern="))
        {
            let name = extern_crate
                .split_once('=')
                .map_or(extern_crate, |(name, _)| name);
            push_metadata_part(&mut identity, b"rustc-extern", OsStr::new(name));
            continue;
        }
        let normalized = normalize_rustc_argument(
            argument,
            source_root,
            target_root,
            unit.manifest_dir.as_deref(),
        );
        push_metadata_part(&mut identity, b"rustc-argument", &normalized);
    }

    let hash = vos::crypto::blake2b_hash::<16>(RUSTC_UNIT_METADATA_DOMAIN, &[&identity]);
    format!("vos-actor-{}", hex::encode(hash))
}

fn push_metadata_part(output: &mut Vec<u8>, label: &[u8], value: &OsStr) {
    push_metadata_bytes(output, label);
    push_metadata_bytes(output, value.to_string_lossy().as_bytes());
}

fn push_metadata_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn normalize_rustc_argument(
    argument: &OsStr,
    source_root: &Path,
    target_root: &OsStr,
    manifest_dir: Option<&Path>,
) -> OsString {
    let mut value = argument.to_string_lossy().replace('\\', "/");
    let target_root = target_root.to_string_lossy().replace('\\', "/");
    if !target_root.is_empty() {
        value = value.replace(&target_root, "vos-target");
    }
    let source_root = source_root.to_string_lossy().replace('\\', "/");
    if !source_root.is_empty() {
        value = value.replace(&source_root, "vos-source");
    }
    if let Some(manifest_dir) = manifest_dir {
        let manifest_dir = manifest_dir.to_string_lossy().replace('\\', "/");
        if !manifest_dir.is_empty()
            && Path::new(manifest_dir.as_str())
                .strip_prefix(source_root.as_str())
                .is_err()
        {
            value = value.replace(&manifest_dir, "vos-package");
        }
    }
    OsString::from(value)
}

fn canonical_package_source(manifest_dir: &Path, source_root: &Path) -> OsString {
    if let Ok(relative) = manifest_dir.strip_prefix(source_root) {
        return OsString::from(format!(
            "workspace/{}",
            relative.to_string_lossy().replace('\\', "/")
        ));
    }

    let normalized = manifest_dir.to_string_lossy().replace('\\', "/");
    for marker in ["/registry/src/", "/git/checkouts/"] {
        if let Some(index) = normalized.find(marker) {
            // The suffix contains Cargo's stable registry/repository identity
            // and package/checkout identity, but not CARGO_HOME.
            return OsString::from(format!("cargo/{}", &normalized[index + marker.len()..]));
        }
    }

    // Toolchain and unusual external path packages have no stable absolute
    // location. Package name/version/repository and normalized rustc inputs
    // still distinguish their compilation units without embedding that path.
    OsString::from("external")
}

fn actor_build_root(project: &Path) -> anyhow::Result<PathBuf> {
    project
        .ancestors()
        .find(|candidate| {
            candidate.join(".cargo/config.toml").is_file()
                && candidate.join("riscv64em-vos.json").is_file()
        })
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "{} is missing the VOS .cargo/config.toml and riscv64em-vos.json build configuration",
                project.display()
            )
        })
}

fn actor_names_from_manifest(manifest: &str) -> anyhow::Result<(String, String)> {
    let manifest: toml::Value = manifest
        .parse()
        .map_err(|error| anyhow!("parse actor Cargo.toml: {error}"))?;
    let package_name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("actor Cargo.toml needs a non-empty [package].name"))?;
    let target_name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .unwrap_or_else(|| package_name.replace('-', "_"));
    Ok((package_name, target_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "vosx-build-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn canonical_wrapper_replaces_path_dependent_cargo_metadata() {
        let unit = RustcUnitIdentity {
            package_name: "counter".into(),
            package_version: "1.0.0".into(),
            manifest_dir: Some("/checkout/actors/counter".into()),
            ..Default::default()
        };
        let arguments = [
            "--crate-name",
            "counter",
            "-C",
            "metadata=checkout-specific",
            "-Cmetadata=also-checkout-specific",
            "--emit=link",
        ]
        .map(OsString::from);
        let canonical = canonical_rustc_arguments(
            arguments,
            OsStr::new("/checkout"),
            OsStr::new("/checkout/target/vosx-canonical/cache-a"),
            &unit,
        );
        assert_eq!(&canonical[..3], ["--crate-name", "counter", "--emit=link"]);
        assert!(
            canonical[3]
                .to_string_lossy()
                .starts_with("-Cmetadata=vos-actor-")
        );
        assert_eq!(canonical[4], "--remap-path-prefix=/checkout=vos-source");
        assert_eq!(
            canonical[5],
            "--remap-path-prefix=/checkout/target/vosx-canonical/cache-a=vos-target"
        );
    }

    #[test]
    fn canonical_metadata_is_checkout_independent() {
        let arguments = |checkout: &str| {
            let cache = checkout.trim_start_matches("/checkout-");
            [
                "--crate-name".into(),
                "counter".into(),
                format!("{checkout}/actors/counter/src/lib.rs").into(),
                "--out-dir".into(),
                format!("{checkout}/target/vosx-canonical/cache-{cache}/release/deps").into(),
                "-Cmetadata=checkout-specific".into(),
                format!("-Cextra-filename=-{}", checkout.trim_start_matches('/')).into(),
                "--extern".into(),
                format!("vos={checkout}/target/release/deps/libvos-checkout.rlib").into(),
                "--cfg".into(),
                "feature=\"default\"".into(),
            ]
        };
        let unit = |checkout: &str| RustcUnitIdentity {
            package_name: "counter".into(),
            package_version: "1.0.0".into(),
            manifest_dir: Some(format!("{checkout}/actors/counter").into()),
            ..Default::default()
        };
        assert_eq!(
            canonical_rustc_unit_metadata(
                &arguments("/checkout-a"),
                OsStr::new("/checkout-a"),
                OsStr::new("/checkout-a/target/vosx-canonical/cache-a"),
                &unit("/checkout-a"),
            ),
            canonical_rustc_unit_metadata(
                &arguments("/checkout-b"),
                OsStr::new("/checkout-b"),
                OsStr::new("/checkout-b/target/vosx-canonical/cache-b"),
                &unit("/checkout-b"),
            ),
        );
    }

    #[test]
    fn canonical_metadata_distinguishes_cargo_units() {
        let arguments = ["--crate-name", "shared", "src/lib.rs"].map(OsString::from);
        let unit = |version: &str, source: &str| RustcUnitIdentity {
            package_name: "shared".into(),
            package_version: version.into(),
            manifest_dir: Some(source.into()),
            ..Default::default()
        };
        let metadata = |version: &str, source: &str| {
            canonical_rustc_unit_metadata(
                &arguments,
                OsStr::new("/workspace"),
                OsStr::new("/workspace/target/vosx-canonical/cache"),
                &unit(version, source),
            )
        };

        assert_ne!(
            metadata("1.0.0", "/cargo/registry/src/index/shared-1.0.0"),
            metadata("2.0.0", "/cargo/registry/src/index/shared-2.0.0"),
        );
        assert_ne!(
            metadata("1.0.0", "/cargo/registry/src/index-a/shared-1.0.0"),
            metadata("1.0.0", "/cargo/registry/src/index-b/shared-1.0.0"),
        );
        assert_ne!(
            metadata("1.0.0", "/workspace/one/shared"),
            metadata("1.0.0", "/workspace/two/shared"),
        );
    }

    #[test]
    fn project_output_uses_the_cargo_target_name() {
        assert_eq!(
            actor_names_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"
                "#,
            )
            .unwrap(),
            ("private-age".into(), "private_age".into())
        );
        assert_eq!(
            actor_names_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"
                    [lib]
                    name = "age_claim"
                "#,
            )
            .unwrap(),
            ("private-age".into(), "age_claim".into())
        );
        assert!(actor_names_from_manifest("[workspace]").is_err());
    }

    #[test]
    fn workspace_member_builds_from_the_actor_workspace_root() {
        let member = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/actors/counter");
        let root = actor_build_root(&member).unwrap();
        assert_eq!(
            root.file_name().and_then(|name| name.to_str()),
            Some("actors")
        );
        assert_eq!(
            root.join("target/riscv64em-vos/release/counter.elf"),
            root.join("target/riscv64em-vos/release")
                .join(format!("{}.elf", "counter".replace('-', "_")))
        );
    }

    #[test]
    fn constructor_metadata_matches_macro_spacing_without_erasing_type_identity() {
        use sdk::schema::{ConstructorArgument, ConstructorContract, ParsedSchema};
        use vos::metadata::{ParsedField, ParsedMeta};
        let metadata = ParsedMeta {
            actor_name: "LocalSigner".into(),
            messages: vec![],
            constructor: vec![ParsedField {
                name: "secret_seed".into(),
                ty: "[u8;32]".into(),
            }],
            doc: String::new(),
            crdt: false,
            provable: false,
        };
        let mut schema = ParsedSchema {
            constructor: ConstructorContract::RequiredNamed(vec![ConstructorArgument {
                name: "secret_seed".into(),
                type_identity: "local_signer::[u8; 32]".into(),
            }]),
            fields: vec![],
            methods: vec![],
        };
        validate_constructor_metadata(&metadata, &schema).unwrap();
        for bad in [
            "local_signer::[u8; 31]",
            "local_signer::[i8; 32]",
            "[u8; 32]",
            "local_signer::Other[u8; 32]",
        ] {
            let ConstructorContract::RequiredNamed(arguments) = &mut schema.constructor else {
                unreachable!()
            };
            arguments[0].type_identity = bad.into();
            assert!(
                validate_constructor_metadata(&metadata, &schema).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn repeated_actor_builds_emit_one_identical_pvm_and_package() {
        use vos::metadata::{ActorMeta, MessageMeta};

        const META: ActorMeta = ActorMeta {
            actor_name: "deterministic-counter",
            messages: &[MessageMeta {
                name: "value",
                is_query: true,
                fields: &[],
                returns: "u64",
                doc: "",
                timeout_ms: 0,
                mode: 0,
                attested: false,
                capability: None,
                space_role: None,
                actor_role: None,
            }],
            constructor: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
            provable: false,
        };

        let temp = TempDir::new("deterministic");
        let mut actor = vos_pvm_compiler::assembler::Assembler::new();
        actor.trap();
        let actor_pvm = actor.build_standard();
        let (metadata, metadata_len) = vos::metadata::encode::<512>(&META);
        const AGENT_SCHEMA: sdk::schema::SchemaMeta = sdk::schema::SchemaMeta {
            constructor: sdk::schema::ConstructorMeta::Forbidden,
            fields: &[],
            methods: &[sdk::schema::MethodMeta {
                source_index: 0,
                name: "value",
                mode: sdk::MethodMode::Query,
                explicit: false,
            }],
        };
        const AUTHORIZATIONS: &[vos::metadata::AgentMethodAuthorizationMeta] =
            &[vos::metadata::AgentMethodAuthorizationMeta {
                name: "value",
                selector: vos::metadata::AgentAuthorizationSelectorMeta::Public,
            }];
        let (agent_schema, agent_schema_len) = sdk::schema::encode::<512>(&AGENT_SCHEMA);
        let (authorizations, authorizations_len) =
            vos::metadata::encode_agent_authorizations::<512>(AUTHORIZATIONS);
        std::fs::write(temp.0.join("actor.pvm"), &actor_pvm).unwrap();
        std::fs::write(temp.0.join("actor.meta"), &metadata[..metadata_len]).unwrap();
        std::fs::write(
            temp.0.join("actor.agent"),
            &agent_schema[..agent_schema_len],
        )
        .unwrap();
        std::fs::write(
            temp.0.join("actor.auth"),
            &authorizations[..authorizations_len],
        )
        .unwrap();
        let build_args = |out_dir| Args {
            program: temp.0.join("actor.pvm"),
            name: None,
            out_dir,
            method_policy: None,
            schemas: Some(temp.0.join("actor.meta")),
            agent_schema: Some(temp.0.join("actor.agent")),
            agent_authorizations: Some(temp.0.join("actor.auth")),
            tasks: vec![],
            crdt: false,
            scheduling: false,
            proof_system: None,
        };
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        let signer = libp2p::identity::Keypair::generate_ed25519();

        let missing_metadata = run_with_signer(
            Args {
                program: temp.0.join("actor.pvm"),
                name: None,
                out_dir: temp.0.join("missing-metadata"),
                method_policy: None,
                schemas: None,
                agent_schema: Some(temp.0.join("actor.agent")),
                agent_authorizations: Some(temp.0.join("actor.auth")),
                tasks: vec![],
                crdt: false,
                scheduling: false,
                proof_system: None,
            },
            &signer,
        )
        .unwrap_err()
        .to_string();
        assert!(missing_metadata.contains("pass --metadata with its exact bytes"));
        let missing_execution_schema = run_with_signer(
            Args {
                program: temp.0.join("actor.pvm"),
                name: None,
                out_dir: temp.0.join("missing-agent-schema"),
                method_policy: None,
                schemas: Some(temp.0.join("actor.meta")),
                agent_schema: None,
                agent_authorizations: Some(temp.0.join("actor.auth")),
                tasks: vec![],
                crdt: false,
                scheduling: false,
                proof_system: None,
            },
            &signer,
        )
        .unwrap_err()
        .to_string();
        assert!(missing_execution_schema.contains("pass --agent-schema with its exact bytes"));

        run_with_signer(build_args(first.clone()), &signer).unwrap();
        run_with_signer(build_args(second.clone()), &signer).unwrap();

        assert_eq!(
            std::fs::read(first.join("deterministic-counter.pvm")).unwrap(),
            actor_pvm,
        );
        assert_eq!(
            std::fs::read(first.join("deterministic-counter.pvm")).unwrap(),
            std::fs::read(second.join("deterministic-counter.pvm")).unwrap(),
        );
        assert_eq!(
            std::fs::read(first.join("deterministic-counter.vos")).unwrap(),
            std::fs::read(second.join("deterministic-counter.vos")).unwrap(),
        );
        let package_bytes = std::fs::read(first.join("deterministic-counter.vos")).unwrap();
        assert_eq!(package_bytes.get(..4), Some(b"VOS3".as_slice()));
        let package = sdk::package::PackageEnvelope::decode(&package_bytes).unwrap();
        package.validate_shape().unwrap();
        let sdk::package::PackageManifest::Actor(manifest) = &package.manifest else {
            panic!("actor build must emit an Actor manifest")
        };
        assert_eq!(manifest.requirements.lanes, sdk::LaneSet::NONE);
        assert!(!manifest.scheduling);
        assert_eq!(package.actor_program_bytes().unwrap(), actor_pvm);
        assert_eq!(manifest.program, sdk::BlobRef::of_bytes(&actor_pvm));
        assert!(matches!(
            package.actor_schema().unwrap().constructor,
            sdk::schema::ConstructorContract::Forbidden
        ));
        assert!(
            package
                .task_dependency_set()
                .unwrap()
                .dependencies
                .is_empty()
        );
        assert!(!first.join("deterministic-counter.attestation.pvm").exists());
        assert_eq!(std::fs::read_dir(first).unwrap().count(), 2);
    }

    #[test]
    fn execution_entry_markers_reject_cross_packaging() {
        const SCHEMA: vos::agent::schema::SchemaMeta = vos::agent::schema::SchemaMeta {
            uses_storage: false,
            fields: &[],
            methods: &[vos::agent::schema::MethodMeta {
                name: "get",
                mode: vos::agent::MethodMode::Query,
                explicit: false,
            }],
        };
        let encoded = |entry| {
            let (bytes, len) = vos::agent::schema::encode_with_entry::<512>(&SCHEMA, entry);
            bytes[..len].to_vec()
        };
        let path = Path::new("actor.elf");
        let service = encoded(vos::agent::schema::ExecutionEntryKind::ServiceActor);
        let agent = encoded(vos::agent::schema::ExecutionEntryKind::AgentActor);
        let task = encoded(vos::agent::schema::ExecutionEntryKind::Task);

        assert!(
            require_execution_entry(
                &service,
                vos::agent::schema::ExecutionEntryKind::ServiceActor,
                path,
            )
            .is_ok()
        );
        assert!(
            require_execution_entry(
                &agent,
                vos::agent::schema::ExecutionEntryKind::AgentActor,
                path,
            )
            .is_ok()
        );
        assert!(
            require_execution_entry(&task, vos::agent::schema::ExecutionEntryKind::Task, path,)
                .is_ok()
        );
        assert!(
            require_execution_entry(
                &agent,
                vos::agent::schema::ExecutionEntryKind::ServiceActor,
                path,
            )
            .is_err()
        );
        assert!(
            require_execution_entry(
                &service,
                vos::agent::schema::ExecutionEntryKind::AgentActor,
                path,
            )
            .is_err()
        );
        assert!(
            require_execution_entry(&agent, vos::agent::schema::ExecutionEntryKind::Task, path,)
                .is_err()
        );
    }
}
