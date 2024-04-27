//! Magnetar Fields:
//!
//! Most of the code in here and the modules within were copied from
//! curve curve25519-dalek and adapted to be const. Since the intended
//! use case of is_on_curve is not intended to be used with any secrets,
//! there were constant time operations that were replaced with unsafer
//! counterparts. As such, this is not a cryptographically safe
//! implementation. It is only intended to be used at compile time with
//! public keys. For the sake of being as uninvasive as possible, there
//! are some relic constant time implementations for some operations,
//! and there may be some misnamed functions.
//!
//! There is a test in this module which checks that the is_on_curve
//! evaluation agrees with a large batch of random keys.

use sha2_const_stable::Sha256;

mod choice;
mod field_element;

use choice::Choice;
use field_element::FieldElement;

// ------------------------------------------------------------------------
// Compressed points
// ------------------------------------------------------------------------

/// In "Edwards y" / "Ed25519" format, the curve point \\((x,y)\\) is
/// determined by the \\(y\\)-coordinate and the sign of \\(x\\).
///
/// The first 255 bits of a `CompressedEdwardsY` represent the
/// \\(y\\)-coordinate.  The high bit of the 32nd byte gives the sign of
/// \\(x\\).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct CompressedEdwardsY(pub [u8; 32]);

#[derive(Copy, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct EdwardsPoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

/// Do not use as part of a protocol that deals with secrets!
/// Only use to evaluate if
pub const fn crypto_unsafe_is_on_curve(key: &[u8; 32]) -> bool {
    let (is_valid_y_coord, _, _, _) = decompress_step_1(key);

    // don't need step 2 when checking on curve

    is_valid_y_coord.into()
}

const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

pub const fn derive_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> ([u8; 32], u8) {
    let mut bump = u8::MAX;

    loop {
        let mut hasher = Sha256::new();

        let mut i = 0;
        while i < seeds.len() {
            hasher = hasher.update(seeds[i]);
            i += 1;
        }
        hasher = hasher.update(&[bump]);

        // Solana PDAs also have program id and marker
        hasher = hasher.update(program);
        hasher = hasher.update(PDA_MARKER);

        let candidate = hasher.finalize();

        // If off curve, we're done
        if !crypto_unsafe_is_on_curve(&candidate) {
            return (candidate, bump);
        }

        // Otherwise, check next bump
        bump -= 1;
    }
}

#[rustfmt::skip] // keep alignment of explanatory comments
pub(super) const fn decompress_step_1(
    repr: &[u8; 32],
) -> (Choice, FieldElement, FieldElement, FieldElement) {
    let y = FieldElement::from_bytes(repr);
    let z = FieldElement::ONE;
    let yy = y.square();
    let u = yy.sub(z);                              // u =  y²-1
    let v = yy.mul(FieldElement::EDWARDS_D).add(z); // v = dy²+1
    let (is_valid_y_coord, x) = FieldElement::sqrt_ratio_i(u, v);

    (is_valid_y_coord, x, y, z)
}

#[test]
fn test_on_curve() {
    fn safe_is_on_curve(key: &[u8; 32]) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(key.as_ref())
            .unwrap()
            .decompress()
            .is_some()
    }

    for _ in 0..50_000 {
        let bytes = rand::random::<[u8; 32]>();
        assert_eq!(crypto_unsafe_is_on_curve(&bytes), safe_is_on_curve(&bytes));
    }
}
