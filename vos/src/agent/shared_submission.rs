//! Signed ordinary Shared lifecycle submissions for the native operator.
//!
//! These envelopes authenticate request bytes only. They are not Authority
//! approval, genesis endorsement, finality, or permission to publish a route.

use super::super::genesis::{AgentReplicaCommittee, MAX_AGENT_REPLICA_COMMITTEE_BYTES};
use super::super::package_admission::{AdmittedActorPackage, AdmittedRuntimePackage};
use super::super::sdk::authority::AuthorityCredentialCall;
use super::super::sdk::wire::CanonicalWire as _;
use super::super::sdk::{AgentDescriptor, AgentProfile, InstallActor, ManagementRequest};
use crate::service::ServiceWire as _;
use crate::service::wire::{DecodeError, Decoder, Encoder};

/// SCQ1: length-prefixed AMRQ Create, ACC3 call, admitted VOS3 runtime and
/// the exact AGRM replica committee selected for the Create's descriptor.
#[derive(Clone)]
pub struct SharedCreateSubmission {
    descriptor: AgentDescriptor,
    call: AuthorityCredentialCall,
    runtime: AdmittedRuntimePackage,
    replicas: AgentReplicaCommittee,
}

impl SharedCreateSubmission {
    pub const MAX_BYTES: usize =
        super::LocalCreateSubmission::MAX_BYTES + 4 + MAX_AGENT_REPLICA_COMMITTEE_BYTES;

    pub fn new(
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
        replicas: AgentReplicaCommittee,
    ) -> Result<Self, DecodeError> {
        if descriptor.identity.profile != AgentProfile::Shared
            || call.managed.profile != AgentProfile::Shared
            || replicas.validate_for_clean_descriptor(&descriptor).is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        super::super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| DecodeError::NonCanonical)?;
        super::super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            descriptor,
            call,
            runtime,
            replicas,
        })
    }

    pub fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }

    pub fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"SCQ1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Create(Box::new(self.descriptor.clone()))
                .encode()
                .expect("validated Shared Create"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.runtime.exact_bytes());
        encoder.bytes(&self.replicas.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"SCQ1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        let replicas = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
            || replicas.len() > MAX_AGENT_REPLICA_COMMITTEE_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Create(descriptor) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        let runtime = super::super::package_admission::admit_runtime_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        let decoded =
            AgentReplicaCommittee::decode(replicas).map_err(|_| DecodeError::NonCanonical)?;
        if decoded.encode() != replicas {
            return Err(DecodeError::NonCanonical);
        }
        Self::new(*descriptor, call, runtime, decoded)
    }

    pub fn into_parts(
        self,
    ) -> (
        AgentDescriptor,
        AuthorityCredentialCall,
        AdmittedRuntimePackage,
        AgentReplicaCommittee,
    ) {
        (self.descriptor, self.call, self.runtime, self.replicas)
    }
}

/// SIQ1: the LIQ1 layout for an ordinary Shared Agent's signed Install.
#[derive(Clone)]
pub struct SharedInstallSubmission {
    install: InstallActor,
    call: AuthorityCredentialCall,
    package: AdmittedActorPackage,
}

impl SharedInstallSubmission {
    pub const MAX_BYTES: usize = super::LocalInstallSubmission::MAX_BYTES;

    pub fn new(
        install: InstallActor,
        call: AuthorityCredentialCall,
        package: AdmittedActorPackage,
    ) -> Result<Self, DecodeError> {
        if call.managed.profile != AgentProfile::Shared
            || install.package != *package.package_ref()
            || install.entry.deployment != package.deployment()
            || install.entry.program != package.program()
            || install.producer != package.producer()
        {
            return Err(DecodeError::NonCanonical);
        }
        install
            .validate_for_profile(AgentProfile::Shared)
            .map_err(|_| DecodeError::NonCanonical)?;
        super::super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Install(Box::new(install.clone())),
            call.clone(),
            &super::super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            install,
            call,
            package,
        })
    }

    pub fn install(&self) -> &InstallActor {
        &self.install
    }

    pub fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"SIQ1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Install(Box::new(self.install.clone()))
                .encode()
                .expect("validated Shared Install"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.package.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"SIQ1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Install(install) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        let package = super::super::package_admission::admit_actor_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*install, call, package)
    }

    pub fn into_parts(self) -> (InstallActor, AuthorityCredentialCall, AdmittedActorPackage) {
        (self.install, self.call, self.package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_submissions_refuse_foreign_tags_and_oversized_frames() {
        assert!(matches!(
            SharedCreateSubmission::decode(b"LCQ1"),
            Err(DecodeError::InvalidTag)
        ));
        assert!(matches!(
            SharedInstallSubmission::decode(b"LIQ1"),
            Err(DecodeError::InvalidTag)
        ));
        assert!(matches!(
            SharedCreateSubmission::decode(&vec![0; SharedCreateSubmission::MAX_BYTES + 1]),
            Err(DecodeError::LimitExceeded)
        ));
        assert!(matches!(
            SharedInstallSubmission::decode(&vec![0; SharedInstallSubmission::MAX_BYTES + 1]),
            Err(DecodeError::LimitExceeded)
        ));
        assert!(SharedCreateSubmission::decode(b"SCQ1").is_err());
        assert!(SharedInstallSubmission::decode(b"SIQ1").is_err());
    }
}
