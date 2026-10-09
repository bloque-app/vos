//! A real VOS proof through `fc-pallet-spaces`'s `anchor` call.
//!
//! `fixtures/anchor1.*` is a STANDARD proof made by `fixtures/gen` with VOS's prover. Its program
//! commits to one `AnchorStatement`: Space `0` (the first registered), epoch `0`, anchor `1`, from
//! the zero root to `[1; 32]`, on a chain whose genesis hash is zero (as in a test externality).
//! See `fixtures/README.md`.

use codec::Encode;
use fc_pallet_spaces::{self as pallet_spaces, Error, Heads, Pallet as Spaces};
use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    traits::{ConstU32, ConstU8},
    BoundedVec,
};
use frame_system::{EnsureRoot, EnsureSigned};
use vos_spaces_verifier::{ProofVerifier, VerifyError, VosPolicy, VosVerifier};

const PROOF: &[u8] = include_bytes!("../fixtures/anchor1.proof");
const COMMITMENT: &[u8; 32] = include_bytes!("../fixtures/anchor1.commitment");
const PUBLIC: &[u8] = include_bytes!("../fixtures/anchor1.public");
const OUTPUT: &[u8] = include_bytes!("../fixtures/anchor1.output");

const SPACE: u32 = 0;
const GENESIS: [u8; 32] = [0; 32];
const ROOT: [u8; 32] = [1; 32];

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        SpacesPallet: pallet_spaces,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

parameter_types! {
    pub const Standard: VosPolicy = VosPolicy::Standard;
    pub const SpacesPalletId: frame_support::PalletId = frame_support::PalletId(*b"fc/space");
}

type Verifier = VosVerifier<Standard, ConstU8<18>>;

impl pallet_spaces::Config for Test {
    type PalletId = SpacesPalletId;
    type SpaceId = u32;
    type BindKey = u32;
    type CreateOrigin = EnsureSigned<u64>;
    type ResetOrigin = EnsureRoot<u64>;
    type Verifier = Verifier;
    type MaxProofLen = ConstU32<{ 1536 * 1024 }>;
    type MaxPublicLen = ConstU32<{ 16 * 1024 }>;
    type WeightInfo = ();
}

fn authority() -> OriginCaller {
    OriginCaller::system(frame_system::RawOrigin::Signed(1))
}

fn ext() -> sp_io::TestExternalities {
    let mut ext = sp_io::TestExternalities::new(Default::default());
    ext.execute_with(|| {
        System::set_block_number(1);
        assert_ok!(Spaces::<Test>::register(
            RuntimeOrigin::signed(1),
            authority(),
            *COMMITMENT,
            GENESIS
        ));
    });
    ext
}

fn anchor(
    number: u64,
    root: [u8; 32],
    proof: &[u8],
    public: &[u8],
) -> frame_support::dispatch::DispatchResultWithPostInfo {
    Spaces::<Test>::anchor(
        RuntimeOrigin::signed(2),
        SPACE,
        number,
        root,
        BoundedVec::truncate_from(proof.to_vec()),
        BoundedVec::truncate_from(public.to_vec()),
    )
}

#[test]
fn the_fixture_commits_to_the_pallets_statement() {
    ext().execute_with(|| {
        let head = Heads::<Test>::get(SPACE).unwrap();
        assert_eq!(
            Spaces::<Test>::anchor_statement(SPACE, &head, ROOT).encode(),
            OUTPUT,
            "the pallet's statement changed: regenerate the fixture (fixtures/README.md)"
        );
    });
}

#[test]
fn a_real_proof_anchors() {
    ext().execute_with(|| {
        assert_ok!(anchor(1, ROOT, PROOF, PUBLIC));
        let head = Heads::<Test>::get(SPACE).unwrap();
        assert_eq!((head.number, head.root), (1, ROOT));
    });
}

#[test]
fn a_real_proof_is_bound_to_its_statement() {
    ext().execute_with(|| {
        // Another root.
        assert_noop!(anchor(1, [2; 32], PROOF, PUBLIC), Error::<Test>::NotBound);
        // Another public input.
        assert_noop!(anchor(1, ROOT, PROOF, b"other"), Error::<Test>::NotBound);
        // The head moved: a reset to the same root opens a new epoch.
        assert_ok!(Spaces::<Test>::set_current_head(
            RuntimeOrigin::root(),
            SPACE,
            GENESIS
        ));
        assert_noop!(anchor(1, ROOT, PROOF, PUBLIC), Error::<Test>::NotBound);
    });
}

#[test]
fn a_real_proof_is_bound_to_its_space() {
    ext().execute_with(|| {
        // A second Space (id 1) running the same program from the same genesis.
        assert_ok!(Spaces::<Test>::register(
            RuntimeOrigin::signed(1),
            authority(),
            *COMMITMENT,
            GENESIS
        ));
        assert_noop!(
            Spaces::<Test>::anchor(
                RuntimeOrigin::signed(2),
                SPACE + 1,
                1,
                ROOT,
                BoundedVec::truncate_from(PROOF.to_vec()),
                BoundedVec::truncate_from(PUBLIC.to_vec()),
            ),
            Error::<Test>::NotBound
        );
    });
}

#[test]
fn a_real_proof_of_another_program_is_refused() {
    ext().execute_with(|| {
        // The Space's authority moves it to another program: the proof no longer anchors.
        assert_ok!(Spaces::<Test>::set_program(
            RuntimeOrigin::signed(1),
            SPACE,
            [9; 32]
        ));
        assert_noop!(anchor(1, ROOT, PROOF, PUBLIC), Error::<Test>::WrongProgram);
        assert_eq!(
            Verifier::verify(&[9; 32], PROOF, PUBLIC, OUTPUT),
            Err(VerifyError::WrongProgram)
        );
    });
}

#[test]
fn a_tampered_real_proof_is_refused() {
    ext().execute_with(|| {
        let mut tampered = PROOF.to_vec();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;
        assert!(anchor(1, ROOT, &tampered, PUBLIC).is_err());
        assert_eq!(Heads::<Test>::get(SPACE).unwrap().number, 0);
    });
}

#[test]
fn undecodable_bytes_are_malformed() {
    ext().execute_with(|| {
        assert_noop!(
            anchor(1, ROOT, &[1, 2, 3], PUBLIC),
            Error::<Test>::MalformedProof
        );
    });
}
