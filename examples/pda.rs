use const_crypto::{bs58, ed25519, sha2, sha3};

/// Uses const bs58
pub const PROGRAM_KEY: [u8; 32] = bs58::from_str("11111111111111111111111111111111");

/// Uses const ed25519 (and thus const sha2 internally)
pub const PROGRAM_DERIVED_ADDRESS: [u8; 32] =
    ed25519::derive_program_address(&[b"seed"], &PROGRAM_KEY).0;

// the address is off curve
const _: () = assert!(!ed25519::crypto_unsafe_is_on_curve(
    &PROGRAM_DERIVED_ADDRESS
));

pub fn main() {
    pub const KECCAK_DEMO: [u8; 32] = sha3::Keccak256::new().update(b"const-keccak").finalize();
    pub const SHA3_256_DEMO: [u8; 32] = sha3::Sha3_256::new().update(b"const-sha3").finalize();
    pub const SHA256_DEMO: [u8; 32] = sha2::Sha256::new().update(b"const-sha2").finalize();

    println!("pda      = {PROGRAM_DERIVED_ADDRESS:?}\n");
    println!("keccak   = {KECCAK_DEMO:?}\n");
    println!("sha3_256 = {SHA3_256_DEMO:?}\n");
    println!("sha256   = {SHA256_DEMO:?}\n");
}
