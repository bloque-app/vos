use alloc::vec::Vec;
use core::fmt;

fn digest<const N: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; N] {
    crate::blake2b::digest::<N>(domain, parts)
}

macro_rules! id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            Clone,
            Copy,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
        )]
        #[rkyv(crate = rkyv)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "("))?;
                for byte in &self.0[..4] {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str("…)")
            }
        }
    };
}

id_type!(Hash, "Hash");
id_type!(SpaceId, "SpaceId");
id_type!(AgentId, "AgentId");
id_type!(ActorId, "ActorId");
id_type!(PrincipalId, "PrincipalId");
id_type!(NodeId, "NodeId");
id_type!(CredentialId, "CredentialId");
id_type!(ProducerId, "ProducerId");
id_type!(ProgramId, "ProgramId");
id_type!(DeploymentId, "DeploymentId");
id_type!(InstallationId, "InstallationId");
id_type!(InvocationId, "InvocationId");
id_type!(CallId, "CallId");
id_type!(ScheduleId, "ScheduleId");
id_type!(ChangeId, "ChangeId");
id_type!(OperationId, "OperationId");
id_type!(CapabilityId, "CapabilityId");
id_type!(RoleId, "RoleId");

impl Hash {
    pub fn digest(domain: &[u8], parts: &[&[u8]]) -> Self {
        Self(digest::<32>(domain, parts))
    }
}

impl CapabilityId {
    /// Stable identifier for one space-level permission.
    pub fn named(name: &str) -> Self {
        Self(digest::<32>(b"vos/capability", &[name.as_bytes()]))
    }
}

impl RoleId {
    /// Stable identifier for a named role inside one space.
    pub fn named(space: SpaceId, name: &str) -> Self {
        Self(digest::<32>(
            b"vos/role",
            &[space.as_bytes(), name.as_bytes()],
        ))
    }
}

impl ProgramId {
    /// Canonical PVM bytes, not an ELF or a JIT artifact, define program
    /// identity.
    pub fn of_pvm(pvm: &[u8]) -> Self {
        Self(digest::<32>(b"vos/program/standard-pvm", &[pvm]))
    }
}

impl SpaceId {
    /// Derive a durable space identity from its founding Principal and a
    /// caller-generated creation nonce. The Principal is deliberately not a
    /// transport Node or login Credential, and the space domain is distinct
    /// from the Agent identity domain.
    pub fn derive(creator: PrincipalId, nonce: &[u8]) -> Self {
        Self(digest::<32>(b"vos/space/id", &[creator.as_bytes(), nonce]))
    }
}

impl AgentId {
    /// Derive a durable agent identity from its space, owner, and
    /// caller-chosen creation nonce.
    pub fn derive(space: SpaceId, owner: PrincipalId, nonce: &[u8]) -> Self {
        Self(digest::<32>(
            b"vos/agent/id",
            &[space.as_bytes(), owner.as_bytes(), nonce],
        ))
    }
}

impl PrincipalId {
    /// A principal is the long-lived human or operator identity, independent
    /// of any one node or login credential.
    pub fn of_public_key(public_key: &[u8]) -> Self {
        Self(digest::<32>(b"vos/principal", &[public_key]))
    }
}

impl NodeId {
    /// Bind a replica node to its complete authenticated transport identity.
    pub fn of_authenticated_peer(peer_id: &[u8]) -> Self {
        Self(digest::<32>(b"vos/node", &[peer_id]))
    }
}

impl CredentialId {
    /// Stable identifier of one independently revocable login credential.
    pub fn of_public_key(public_key: &[u8]) -> Self {
        Self(digest::<32>(b"vos/credential", &[public_key]))
    }
}

impl ActorId {
    /// Stable identity of one top-level actor in an agent namespace.
    pub fn top_level(agent: AgentId, name: &str) -> Self {
        Self(digest::<32>(
            b"vos/actor/top-level",
            &[agent.as_bytes(), name.as_bytes()],
        ))
    }

    /// Stable identity of one owned child in its parent's namespace.
    pub fn owned_child(parent: Self, name: &str) -> Self {
        Self(digest::<32>(
            b"vos/actor/owned-child",
            &[&parent.0, name.as_bytes()],
        ))
    }
}

impl ProducerId {
    pub fn of_public_key(public_key: &[u8]) -> Self {
        Self(digest::<32>(b"vos/producer", &[public_key]))
    }
}

impl InvocationId {
    const INGRESS_IDEMPOTENCY_PREFIX: [u8; 8] = *b"VOSINGR!";

    /// Derive a stable invocation identifier from an application namespace and
    /// caller-provided nonce. Length framing prevents ambiguous concatenation.
    pub fn derive(namespace: &[u8], nonce: &[u8]) -> Self {
        let namespace_len = (namespace.len() as u64).to_le_bytes();
        let nonce_len = (nonce.len() as u64).to_le_bytes();
        Self(digest::<32>(
            b"vos/invocation",
            &[&namespace_len, namespace, &nonce_len, nonce],
        ))
    }

    pub fn for_ingress_idempotency(
        principal: PrincipalId,
        target: ActorId,
        ingress: &str,
        key: &[u8],
    ) -> Self {
        let mut nonce = Vec::with_capacity(64 + ingress.len() + key.len() + 16);
        nonce.extend_from_slice(&principal.0);
        nonce.extend_from_slice(&target.0);
        nonce.extend_from_slice(&(ingress.len() as u64).to_le_bytes());
        nonce.extend_from_slice(ingress.as_bytes());
        nonce.extend_from_slice(&(key.len() as u64).to_le_bytes());
        nonce.extend_from_slice(key);
        let mut invocation = Self::derive(b"vos/ingress/idempotency-key", &nonce);
        invocation.0[..Self::INGRESS_IDEMPOTENCY_PREFIX.len()]
            .copy_from_slice(&Self::INGRESS_IDEMPOTENCY_PREFIX);
        invocation
    }

    /// Whether this identifier belongs to the durable ingress-result
    /// namespace. Public for protocol consumers; applications should normally
    /// use [`Self::for_ingress_idempotency`] instead.
    #[doc(hidden)]
    pub fn retains_idempotent_result(self) -> bool {
        self.0.starts_with(&Self::INGRESS_IDEMPOTENCY_PREFIX)
    }

    /// The nth await in an invocation always derives the same call id.
    pub fn call_id(self, await_ordinal: u64) -> CallId {
        CallId(digest::<32>(
            b"vos/call",
            &[&self.0, &await_ordinal.to_le_bytes()],
        ))
    }

    pub const fn root_reply_id(self) -> CallId {
        CallId(self.0)
    }

    pub fn for_call(call: CallId) -> Self {
        Self(digest::<32>(b"vos/call-invocation", &[&call.0]))
    }

    /// One interval occurrence has one replay-stable invocation identity.
    pub fn for_schedule(schedule: ScheduleId, due_slot: u64) -> Self {
        Self(digest::<32>(
            b"vos/schedule/invocation",
            &[schedule.as_bytes(), &due_slot.to_le_bytes()],
        ))
    }
}

impl ScheduleId {
    /// Derive a stable timer identity in one actor namespace. Length framing
    /// keeps caller-selected nonces unambiguous and makes retries idempotent.
    pub fn derive(agent: AgentId, actor: ActorId, nonce: &[u8]) -> Self {
        Self(digest::<32>(
            b"vos/schedule/id",
            &[
                agent.as_bytes(),
                actor.as_bytes(),
                &(nonce.len() as u64).to_le_bytes(),
                nonce,
            ],
        ))
    }
}

impl ChangeId {
    /// Stable operation identity within one atomically batched CRDT change.
    pub fn operation(
        self,
        actor: ActorId,
        dispatch_ordinal: u32,
        field: Hash,
        operation_ordinal: u32,
    ) -> OperationId {
        OperationId(digest::<32>(
            b"vos/crdt-operation-id",
            &[
                &self.0,
                &actor.0,
                &dispatch_ordinal.to_le_bytes(),
                &field.0,
                &operation_ordinal.to_le_bytes(),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_ids_are_stable_and_fully_scoped() {
        let space = SpaceId([1; 32]);
        let owner = PrincipalId([2; 32]);
        assert_eq!(
            AgentId::derive(space, owner, b"nonce"),
            AgentId::derive(space, owner, b"nonce")
        );
        assert_ne!(
            AgentId::derive(space, owner, b"nonce"),
            AgentId::derive(space, owner, b"other")
        );
        assert_ne!(
            AgentId::derive(space, owner, b"nonce"),
            AgentId::derive(space, PrincipalId([3; 32]), b"nonce")
        );
    }

    #[test]
    fn space_ids_are_stable_principal_scoped_and_domain_separated() {
        let creator = PrincipalId([2; 32]);
        let space = SpaceId::derive(creator, b"nonce");
        assert_eq!(space, SpaceId::derive(creator, b"nonce"));
        assert_ne!(space, SpaceId::derive(creator, b"other"));
        assert_ne!(space, SpaceId::derive(PrincipalId([3; 32]), b"nonce"));
        assert_ne!(
            space.0,
            AgentId::derive(SpaceId(creator.0), creator, b"nonce").0
        );
    }

    #[test]
    fn invocation_ids_frame_variable_length_inputs() {
        assert_ne!(
            InvocationId::derive(b"ab", b"c"),
            InvocationId::derive(b"a", b"bc")
        );
    }

    #[test]
    fn call_ids_are_ordinal_scoped() {
        let invocation = InvocationId::derive(b"test", b"nonce");
        assert_eq!(invocation.call_id(3), invocation.call_id(3));
        assert_ne!(invocation.call_id(3), invocation.call_id(4));
        assert_eq!(invocation.root_reply_id().0, invocation.0);
    }

    #[test]
    fn schedule_ids_are_actor_scoped_and_length_framed() {
        let agent = AgentId([1; 32]);
        let actor = ActorId([2; 32]);
        assert_eq!(
            ScheduleId::derive(agent, actor, b"daily"),
            ScheduleId::derive(agent, actor, b"daily")
        );
        assert_ne!(
            ScheduleId::derive(agent, actor, b"daily"),
            ScheduleId::derive(agent, ActorId([3; 32]), b"daily")
        );
        assert_ne!(
            ScheduleId::derive(agent, actor, b"ab"),
            ScheduleId::derive(agent, actor, b"a\0b")
        );
    }

    #[test]
    fn capability_and_role_domains_do_not_overlap() {
        let space = SpaceId([9; 32]);
        assert_ne!(
            CapabilityId::named("developer").0,
            RoleId::named(space, "developer").0
        );
    }
}
