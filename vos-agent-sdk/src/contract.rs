//! Signed compatibility contract shared by actor and runtime packages.

use crate::{
    Hash, MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES,
    MAX_RUNTIME_STATE_BYTES, MAX_TRANSITION_PROOF_MATERIAL_BYTES, RUNTIME_ABI_ID,
    RuntimeCapabilities, RuntimeResourceUsage,
};

/// Actor entry ABI emitted by the canonical actor toolchain.
pub const ACTOR_ABI: u32 = 4;

/// Descriptor committed by [`CONTROL_SCHEMA_ID`].
pub const CONTROL_SCHEMA_DESCRIPTOR: &[u8] = &RUNTIME_ABI_ID.0;

/// Canonical management schema. This constant is BLAKE2b-256 over
/// `vos/agent/control-schema` followed by [`CONTROL_SCHEMA_DESCRIPTOR`].
pub const CONTROL_SCHEMA_ID: Hash = Hash([
    0x02, 0x4f, 0x7f, 0xd6, 0x38, 0x79, 0x55, 0x91, 0x9a, 0x15, 0x5f, 0x44, 0xfc, 0x1e, 0x34, 0x7e,
    0x28, 0x90, 0xea, 0x28, 0x97, 0xf9, 0x30, 0xb1, 0x3a, 0x46, 0x5c, 0x08, 0xa2, 0x99, 0x11, 0x8b,
]);

/// One actor ABI requirement signed into an actor package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorPackageContract {
    pub actor_abi: u32,
}

impl ActorPackageContract {
    pub const fn canonical() -> Self {
        Self {
            actor_abi: ACTOR_ABI,
        }
    }

    pub fn is_valid(self) -> bool {
        self.actor_abi != 0
    }
}

/// Inclusive actor ABI interval implemented by one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorAbiRange {
    pub minimum: u32,
    pub maximum: u32,
}

impl ActorAbiRange {
    pub const fn exact(actor_abi: u32) -> Self {
        Self {
            minimum: actor_abi,
            maximum: actor_abi,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.minimum != 0 && self.minimum <= self.maximum
    }

    pub const fn supports(self, actor_abi: u32) -> bool {
        self.is_valid() && actor_abi >= self.minimum && actor_abi <= self.maximum
    }
}

/// Runtime-owned state-image and catalog-closure ceilings authenticated by
/// an AgentRuntime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourceLimits {
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
    pub max_proof_material_bytes: u64,
}

/// Explicit signed ceilings for logical external actor rows, separate from the
/// state-image limit. Each data lane has its own allowance across actors and
/// incarnations: replica-local usage cannot affect a common Linear/Merge write.
/// Key/value bytes count; inline/runtime metadata, history and physical block
/// overhead need separate bounds. No default silently grants storage authority.
/// Deployment admission may impose stricter ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalStateResourceLimits {
    pub max_rows_per_lane: u64,
    pub max_row_bytes_per_lane: u64,
}

impl ExternalStateResourceLimits {
    pub const fn is_valid(self) -> bool {
        self.max_rows_per_lane != 0 && self.max_row_bytes_per_lane != 0
    }
}

impl RuntimeResourceLimits {
    pub const fn standard() -> Self {
        Self {
            max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
            max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
            && self.max_proof_material_bytes != 0
            && self.max_proof_material_bytes <= MAX_TRANSITION_PROOF_MATERIAL_BYTES
    }
}

/// Per-Agent bounds of one actor invocation, enforced by the runtime from the
/// Agent's state. An Agent that never sets them runs under [`Self::STANDARD`],
/// exactly the bounds a runtime had before they were configurable; its owner
/// may select others up to [`Self::MAXIMUM`] (`ManagementRequest::
/// SetExecutionLimits`). Every value is deterministic Agent state, so every
/// replica and the prover apply the same bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionLimits {
    /// Most actor gas one invocation may carry (`InvocationWork::gas`).
    pub max_invocation_gas: u64,
    /// Most FETCH reads one invocation may make besides one per caller blob:
    /// state lanes, control, message and storage rows.
    pub max_invocation_reads: u32,
    /// Most bytes of one actor state lane, and of the lanes visible to one
    /// invocation together.
    pub max_lane_state_bytes: u32,
}

impl ExecutionLimits {
    /// The bounds before they were configurable: 1 G gas, 16 reads, 48 KiB.
    pub const STANDARD: Self = Self {
        max_invocation_gas: 1_000_000_000,
        max_invocation_reads: 16,
        max_lane_state_bytes: 48 * 1024,
    };
    /// The runtime's hard ceilings, covered by its ProgramId. Gas is bounded by
    /// the host's own outer budget besides; reads by the native work they cause;
    /// lanes by the state image (`MAX_RUNTIME_STATE_BYTES`).
    pub const MAXIMUM: Self = Self {
        max_invocation_gas: 1_000_000_000_000,
        max_invocation_reads: 64 * 1024,
        max_lane_state_bytes: 4 * 1024 * 1024,
    };

    pub const fn is_valid(self) -> bool {
        self.max_invocation_gas != 0
            && self.max_invocation_gas <= Self::MAXIMUM.max_invocation_gas
            && self.max_invocation_reads >= 5
            && self.max_invocation_reads <= Self::MAXIMUM.max_invocation_reads
            && self.max_lane_state_bytes >= 1024
            && self.max_lane_state_bytes <= Self::MAXIMUM.max_lane_state_bytes
    }
}

/// Mutable runtime resource policy selected beneath immutable package limits.
///
/// Every mutable ceiling may be narrowed only when the current usage still
/// fits. Immutable package limits remain the signed upper bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourcePolicy {
    pub max_actors: u32,
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
    pub max_proof_material_bytes: u64,
}

impl RuntimeResourcePolicy {
    pub const fn standard() -> Self {
        Self {
            max_actors: crate::STANDARD_MAX_ACTORS,
            max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
            max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        }
    }

    /// Deterministic initial policy for one descriptor's signed runtime
    /// capabilities and immutable resource limits.
    pub const fn initial(capabilities: RuntimeCapabilities, limits: RuntimeResourceLimits) -> Self {
        Self {
            max_actors: capabilities.max_actors,
            max_runtime_state_bytes: limits.max_runtime_state_bytes,
            max_artifact_references: limits.max_artifact_references,
            max_artifact_referenced_bytes: limits.max_artifact_referenced_bytes,
            max_proof_material_bytes: limits.max_proof_material_bytes,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_actors != 0
            && self.max_actors <= crate::STANDARD_MAX_ACTORS
            && self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
            && self.max_proof_material_bytes != 0
            && self.max_proof_material_bytes <= MAX_TRANSITION_PROOF_MATERIAL_BYTES
    }

    pub const fn is_within(
        self,
        capabilities: RuntimeCapabilities,
        limits: RuntimeResourceLimits,
    ) -> bool {
        self.is_valid()
            && capabilities.max_actors != 0
            && self.max_actors <= capabilities.max_actors
            && limits.is_valid()
            && self.max_runtime_state_bytes <= limits.max_runtime_state_bytes
            && self.max_artifact_references <= limits.max_artifact_references
            && self.max_artifact_referenced_bytes <= limits.max_artifact_referenced_bytes
            && self.max_proof_material_bytes <= limits.max_proof_material_bytes
    }

    pub const fn admits_usage(self, usage: RuntimeResourceUsage) -> bool {
        self.is_valid()
            && usage.actors <= self.max_actors
            && usage.state_bytes <= self.max_runtime_state_bytes
            && usage.artifact_references <= self.max_artifact_references
            && usage.artifact_referenced_bytes <= self.max_artifact_referenced_bytes
            && usage.proof_material_bytes <= self.max_proof_material_bytes
    }
}

/// Durable state migration behavior implemented by a runtime package.
/// Unknown values are rejected by the canonical decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeMigrationPolicy {
    None = 0,
}

/// Complete mandatory contract signed into an AgentRuntime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePackageContract {
    pub lifecycle_abi: Hash,
    pub actor_abis: ActorAbiRange,
    pub control_schema: Hash,
    pub resources: RuntimeResourceLimits,
    pub migration: RuntimeMigrationPolicy,
}

impl RuntimePackageContract {
    pub const fn canonical() -> Self {
        Self {
            lifecycle_abi: RUNTIME_ABI_ID,
            actor_abis: ActorAbiRange::exact(ACTOR_ABI),
            control_schema: CONTROL_SCHEMA_ID,
            resources: RuntimeResourceLimits::standard(),
            migration: RuntimeMigrationPolicy::None,
        }
    }

    pub fn is_valid(self) -> bool {
        let supported_abi = self.lifecycle_abi == RUNTIME_ABI_ID;
        #[cfg(feature = "experimental-state-blocks")]
        let supported_abi =
            supported_abi || self.lifecycle_abi == crate::state_execution::STATE_EXECUTION_ABI_ID;
        supported_abi
            && self.actor_abis.is_valid()
            && self.control_schema.0 == CONTROL_SCHEMA_ID.0
            && self.resources.is_valid()
            && matches!(self.migration, RuntimeMigrationPolicy::None)
    }

    /// Explicit signed opt-in for experimental root/block execution. Host
    /// admission must select a matching executor; merely decoding this
    /// contract does not authorize execution through the released dispatcher.
    #[cfg(feature = "experimental-state-blocks")]
    pub const fn experimental_state_blocks() -> Self {
        Self {
            lifecycle_abi: crate::state_execution::STATE_EXECUTION_ABI_ID,
            resources: RuntimeResourceLimits {
                max_runtime_state_bytes:
                    crate::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32,
                ..RuntimeResourceLimits::standard()
            },
            ..Self::canonical()
        }
    }

    pub fn supports(self, actor: ActorPackageContract) -> bool {
        self.is_valid() && actor.is_valid() && self.actor_abis.supports(actor.actor_abi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_state_contract_requires_explicit_feature_and_identity() {
        let canonical = RuntimePackageContract::canonical();
        assert_eq!(canonical.lifecycle_abi, RUNTIME_ABI_ID);
        let mut external = canonical;
        external.lifecycle_abi = crate::state_execution::STATE_EXECUTION_ABI_ID;
        assert_ne!(external.lifecycle_abi, RUNTIME_ABI_ID);
        assert_eq!(
            external.is_valid(),
            cfg!(feature = "experimental-state-blocks")
        );
        #[cfg(feature = "experimental-state-blocks")]
        {
            let admitted = RuntimePackageContract::experimental_state_blocks();
            assert_eq!(admitted.lifecycle_abi, external.lifecycle_abi);
            assert_eq!(
                admitted.resources.max_runtime_state_bytes,
                crate::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32
            );
            assert!(
                admitted.resources.max_runtime_state_bytes
                    < canonical.resources.max_runtime_state_bytes
            );
        }
        external.resources.max_runtime_state_bytes = 0;
        assert!(
            !external.is_valid(),
            "experimental framing must retain resource validation"
        );
        external = canonical;
        external.lifecycle_abi = Hash([0x77; 32]);
        assert!(!external.is_valid());
    }

    #[test]
    fn actor_abi_interval_is_inclusive_and_fail_closed() {
        let range = ActorAbiRange {
            minimum: 2,
            maximum: 4,
        };
        assert!(!range.supports(1));
        assert!(range.supports(2));
        assert!(range.supports(4));
        assert!(!range.supports(5));
        assert!(
            !ActorAbiRange {
                minimum: 4,
                maximum: 2
            }
            .is_valid()
        );
    }

    #[test]
    fn canonical_runtime_contract_is_explicit_and_bounded() {
        let contract = RuntimePackageContract::canonical();
        assert!(contract.is_valid());
        assert!(contract.supports(ActorPackageContract::canonical()));
        assert_eq!(crate::STANDARD_MAX_ACTORS, 4_096);
        assert_eq!(contract.resources.max_runtime_state_bytes, 4 * 1024 * 1024);
        assert_eq!(
            contract.resources.max_proof_material_bytes,
            64 * 1024 * 1024
        );
        let policy = RuntimeResourcePolicy::initial(
            crate::RuntimeCapabilities::standard(),
            contract.resources,
        );
        assert_eq!(policy, RuntimeResourcePolicy::standard());
        assert!(policy.is_within(crate::RuntimeCapabilities::standard(), contract.resources));
        assert!(policy.admits_usage(crate::RuntimeResourceUsage::default()));
    }

    #[test]
    fn runtime_resource_limits_cover_every_signed_ceiling() {
        let canonical = RuntimeResourceLimits::standard();
        assert!(canonical.is_valid());
        for invalid in [
            RuntimeResourceLimits {
                max_runtime_state_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32 + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_proof_material_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
                ..canonical
            },
        ] {
            assert!(!invalid.is_valid());
        }
    }

    #[test]
    fn rrp1_covers_all_mutable_ceilings_and_current_usage() {
        let standard = RuntimeResourcePolicy::standard();
        let limits = RuntimeResourceLimits::standard();
        let capabilities = RuntimeCapabilities::standard();
        assert_eq!(standard.max_actors, 4_096);
        assert_eq!(
            RuntimeResourcePolicy::initial(capabilities, limits),
            standard
        );
        assert!(standard.is_within(capabilities, limits));

        for invalid in [
            RuntimeResourcePolicy {
                max_actors: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_actors: crate::STANDARD_MAX_ACTORS + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_runtime_state_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32 + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_references: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_referenced_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_proof_material_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
                ..standard
            },
        ] {
            assert!(!invalid.is_valid());
        }

        let narrowed_limits = RuntimeResourceLimits {
            max_runtime_state_bytes: 10,
            max_artifact_references: 11,
            max_artifact_referenced_bytes: 12,
            max_proof_material_bytes: 13,
        };
        let narrowed_capabilities = RuntimeCapabilities {
            max_actors: 9,
            ..capabilities
        };
        let narrowed = RuntimeResourcePolicy::initial(narrowed_capabilities, narrowed_limits);
        assert!(narrowed.is_within(narrowed_capabilities, narrowed_limits));
        assert!(!standard.is_within(narrowed_capabilities, narrowed_limits));

        let usage = RuntimeResourceUsage {
            actors: narrowed.max_actors,
            state_bytes: narrowed.max_runtime_state_bytes,
            artifact_references: narrowed.max_artifact_references,
            artifact_referenced_bytes: narrowed.max_artifact_referenced_bytes,
            proof_material_bytes: narrowed.max_proof_material_bytes,
            ..RuntimeResourceUsage::default()
        };
        assert!(narrowed.admits_usage(usage));
        for over in [
            RuntimeResourceUsage {
                actors: usage.actors + 1,
                ..usage
            },
            RuntimeResourceUsage {
                state_bytes: usage.state_bytes + 1,
                ..usage
            },
            RuntimeResourceUsage {
                artifact_references: usage.artifact_references + 1,
                ..usage
            },
            RuntimeResourceUsage {
                artifact_referenced_bytes: usage.artifact_referenced_bytes + 1,
                ..usage
            },
            RuntimeResourceUsage {
                proof_material_bytes: usage.proof_material_bytes + 1,
                ..usage
            },
        ] {
            assert!(!narrowed.admits_usage(over));
        }
    }

    #[test]
    fn control_schema_pin_matches_descriptor() {
        assert_eq!(
            Hash::digest(b"vos/agent/control-schema", &[CONTROL_SCHEMA_DESCRIPTOR]).0,
            CONTROL_SCHEMA_ID.0
        );
    }
}
