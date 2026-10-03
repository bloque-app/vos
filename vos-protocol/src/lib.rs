//! Canonical, allocation-bounded protocol primitives shared by VOS hosts,
//! agent runtimes, and application actors.
//!
//! This crate deliberately has no host/runtime dependency. It is usable from
//! a standard PVM guest with only `core` and `alloc`.

#![no_std]

extern crate alloc;

pub mod blake2b;
mod identity;
pub mod wire;

pub use identity::{
    ActorId, AgentId, CallId, CapabilityId, ChangeId, CredentialId, DeploymentId, Hash,
    InstallationId, InvocationId, NodeId, OperationId, PrincipalId, ProducerId, ProgramId, RoleId,
    ScheduleId, SpaceId,
};

/// A content-addressed byte string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlobRef {
    pub hash: Hash,
    pub len: u64,
}

impl BlobRef {
    /// Construct the canonical VOS blob identity for `bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            hash: Hash::digest(b"vos/blob", &[bytes]),
            len: bytes.len() as u64,
        }
    }

    /// Verify both the byte length and content commitment.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.len == bytes.len() as u64 && *self == Self::of_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_references_bind_length_and_content() {
        let reference = BlobRef::of_bytes(b"agent package");
        assert!(reference.matches(b"agent package"));
        assert!(!reference.matches(b"agent-package"));
        assert_ne!(reference, BlobRef::of_bytes(b"agent package!"));
    }

    #[test]
    fn crate_surface_is_no_std_and_alloc_only() {
        fn accepts_allocated_value(_: alloc::vec::Vec<u8>) {}
        accepts_allocated_value(alloc::vec![1, 2, 3]);
        assert_eq!(core::mem::size_of::<AgentId>(), 32);
    }
}
