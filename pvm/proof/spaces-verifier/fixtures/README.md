# Real-proof fixtures

`anchor1.*` is a real VOS STARK proof (STANDARD policy, largest log size 16, about 505 KB in
postcard), used by `../tests/anchor.rs`:

| File | What |
|---|---|
| `anchor1.proof` | The postcard-encoded VOS `Proof` |
| `anchor1.commitment` | The program commitment: the Space's program |
| `anchor1.public` | The program's public input |
| `anchor1.output` | The program's output: the encoded `AnchorStatement` for Space `0`, epoch `0`, anchor `1`, from the zero root to `[1; 32]`, on a chain whose genesis hash is zero |

The guest program proves no state transition: it only commits to the statement, so the proof
exercises the whole verification path (decoding, the io-hash binding, the program commitment and
the STARK) through the pallet's `anchor` call. Its commitment depends on the statement, so a
different statement is a different program.

## Regenerating

`gen/` is its own workspace on VOS's prover nightly, with VOS's prover (its lockfile pins
`enum-ordinalize` 4.3.2, which that nightly supports):

    cd gen
    cargo build --release
    ./target/release/vos-spaces-fixture-gen .. anchor1 "$(xxd -p -c 1000 ../anchor1.output)"

The test `the_fixture_commits_to_the_pallets_statement` fails if the pallet's statement encoding
changes; regenerate with the new encoding (`AnchorStatement::encode()` in hex) when it does.
