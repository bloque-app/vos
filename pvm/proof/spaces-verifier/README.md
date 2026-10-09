# vos-spaces-verifier

VOS's STARK verifier (`vos-pvm-proof-verifier`: Circle STARK over M31, on Stwo) as a backend for
Kreivo Spaces: `VosVerifier<Policy, MaxLogSize>` implements the `ProofVerifier` trait of
`fc-pallet-spaces` (frame-contrib, <https://github.com/virto-network/frame-contrib>).

frame-contrib holds the Substrate side (the pallet, the trait, a mock verifier) and is the source of
truth for the trait. This crate holds what depends on VOS: the backend, its real-proof tests, and
the adjustments the verifier needs to build for a runtime.

## In a runtime

```rust
parameter_types! {
    pub const SpacesProofPolicy: vos_spaces_verifier::VosPolicy = vos_spaces_verifier::VosPolicy::Standard;
}

impl fc_pallet_spaces::Config for Runtime {
    type Verifier = vos_spaces_verifier::VosVerifier<SpacesProofPolicy, ConstU8<18>>;
    // ...
}
```

The runtime's workspace root needs the Stwo `[patch]` from this crate's `Cargo.toml` (the wasm
builder copies it into the runtime's wasm project): upstream Stwo depends on `dashmap`, which needs
`std`, so it does not build for `wasm32v1-none`. `getrandom` 0.2's `custom` source is registered by
this crate.

## Tests

`tests/anchor.rs` builds a test runtime with `fc-pallet-spaces` and this verifier, registers a Space
and anchors a real proof (`fixtures/anchor1.*`) through the pallet's `anchor` call; then checks it is
refused for another root, another public input, a moved head, another Space, another program, a
flipped bit and undecodable bytes.

    cargo test

`fc-pallet-spaces` comes from frame-contrib's `pallet-spaces` branch until it is released. To test
against a local frame-contrib checkout:

    cargo test --config 'patch."https://github.com/virto-network/frame-contrib".fc-pallet-spaces.path="<frame-contrib>/pallets/spaces"'

`Cargo.lock` is not committed yet: generate it once the `pallet-spaces` branch carries the pallet
this crate is written against.
