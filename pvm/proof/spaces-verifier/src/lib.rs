//! # VOS's STARK verifier for Kreivo Spaces
//!
//! [`VosVerifier`] implements `fc-pallet-spaces`'s [`ProofVerifier`] with VOS's general-purpose
//! verifier, `vos-pvm-proof-verifier` (Circle STARK over M31, on Stwo). One verifier serves every
//! program: a program is identified by its preprocessed-trace commitment, which is what a Space
//! holds as its program.
//!
//! A proof is the postcard encoding of VOS's `Proof`. The check, cheapest first:
//!
//! 1. decode it, with no trailing bytes ([`VerifyError::Malformed`]);
//! 2. its public input/output hash must be [`io_hash`] of the public input and the pallet's
//!    output, the encoded `AnchorStatement` ([`VerifyError::NotBound`]);
//! 3. its preprocessed-trace commitment must be the Space's program, compared before the
//!    verifier's own preflight, so a proof of another program is refused for the price of decoding
//!    it ([`VerifyError::WrongProgram`]);
//! 4. `verify_standalone_with_options`, with the PCS policy and log-size cap the runtime pins
//!    ([`VerifyError::Invalid`]).
//!
//! **Building for a runtime.** polkadot-sdk's wasm builder targets `wasm32v1-none`, for which the
//! verifier's dependency graph needs two adjustments: Stwo from the fork that makes `dashmap`
//! optional (a `[patch]` at the runtime's workspace root, as in this crate's manifest), and
//! `getrandom` 0.2 with its `custom` feature, registered below with a source that always fails.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::marker::PhantomData;
pub use fc_pallet_spaces::{ProgramId, ProofVerifier, VerifyError};
use frame_support::{traits::Get, weights::Weight};
use vos_pvm_proof_verifier::{verify_standalone_with_options, CommitmentHash, PcsPolicy, Proof};

// getrandom 0.2 (stwo -> starknet-crypto -> starknet-ff) builds for `wasm32v1-none` only with a
// registered source. Verification never draws randomness, so the source always fails.
#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
mod no_entropy {
    fn fail(_: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
    getrandom::register_custom_getrandom!(fail);
}

/// VOS's binding of a program's public input and output (`vos::zk::compute_io_hash`): BLAKE2b-256
/// over a domain tag and the BLAKE2b-256 of each field, each under its own tag, here through
/// `sp-io`'s host function. A VOS program leaves it in registers φ9..φ12 at halt.
pub fn io_hash(public: &[u8], output: &[u8]) -> [u8; 32] {
    fn field(bytes: &[u8]) -> [u8; 32] {
        let mut v = alloc::vec::Vec::with_capacity(15 + bytes.len());
        v.extend_from_slice(b"vos/zk/io-field");
        v.extend_from_slice(bytes);
        sp_io::hashing::blake2_256(&v)
    }
    let mut v = [0u8; 9 + 64];
    v[..9].copy_from_slice(b"vos/zk/io");
    v[9..41].copy_from_slice(&field(public));
    v[41..].copy_from_slice(&field(output));
    sp_io::hashing::blake2_256(&v)
}

/// The PCS shape every accepted proof must have exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VosPolicy {
    /// Blowup 16, 19 queries, 20-bit proof of work: the smaller proofs (about 0.5 MB).
    Standard,
    /// Blowup 4, 38 queries, 20-bit proof of work: faster to prove, larger proofs.
    Mobile,
}

impl VosPolicy {
    fn pcs(self) -> PcsPolicy {
        match self {
            VosPolicy::Standard => PcsPolicy::STANDARD,
            VosPolicy::Mobile => PcsPolicy::MOBILE,
        }
    }
}

/// Picoseconds of `ref_time` charged per proof byte.
///
/// TODO: a placeholder from an early measurement of this verifier inside a Substrate runtime's
/// wasm executor (`frame-omni-bencher`, not reference hardware): an upper envelope through the
/// origin over STANDARD, MOBILE and canonical-shape proofs. Benchmark on reference hardware, per
/// pinned policy, before use.
pub const REF_TIME_PER_PROOF_BYTE: u64 = 55_000;

/// VOS's STARK verifier, with the PCS policy `P` and the log-size cap `L` pinned by the runtime.
pub struct VosVerifier<P, L>(PhantomData<(P, L)>);

impl<P: Get<VosPolicy>, L: Get<u8>> ProofVerifier for VosVerifier<P, L> {
    fn verify(
        program: &ProgramId,
        proof: &[u8],
        public: &[u8],
        output: &[u8],
    ) -> Result<(), VerifyError> {
        let (proof, rest) =
            postcard::take_from_bytes::<Proof>(proof).map_err(|_| VerifyError::Malformed)?;
        if !rest.is_empty() {
            return Err(VerifyError::Malformed);
        }
        if proof.public_io_hash() != io_hash(public, output) {
            return Err(VerifyError::NotBound);
        }
        let commitment = CommitmentHash::from(&program[..]);
        if proof.stark_proof.commitments.first() != Some(&commitment) {
            return Err(VerifyError::WrongProgram);
        }
        verify_standalone_with_options(proof, commitment, L::get().into(), &P::get().pcs())
            .map_err(|_| VerifyError::Invalid)
    }

    /// The proof's bytes are not declared as proof size: `CheckWeight` already counts the
    /// extrinsic's length as PoV, and declaring them again would halve how many proofs fit a block.
    fn weight(proof_len: u32) -> Weight {
        Weight::from_parts(REF_TIME_PER_PROOF_BYTE, 0).saturating_mul(proof_len.into())
    }
}
