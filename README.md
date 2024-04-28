# `const-crypto`

A `#[no_std]` library for `const` sha2/sha3 hashing, ed25519 off-curve point evaluation, and bs58 decoding/encoding with minimal dependencies.

## Features

- We write a `const` implementation of Edwards point decompression and use it to provide a `const` implementation of on/off curve evaluation. This is then used to build a `const` implementation of Solana's `Pubkey::find_program_address`.
    **NOTE: this point decompression implementation is not cryptographically safe; it does not use constant time implementations for the internal math operations, as it is not intended to be used with secrets. Do not reuse.**
- Base58 encoding of 32 byte arrays into strings (and vice versa, i.e. decoding). The encoding is taken from `fd_bs58`, and adapted for `const`/`#[no_std] with some bug fixes.
- Full sha2/sha3 hash suites. Re-exports of `sha2-const-stable` (authored by yours truly) and `keccak-const` (authored by [OffChainLabs](https://github.com/OffchainLabs/keccak-const))

## Usage

The file `examples/pda.rs` concisely demonstrates all functionality:

```rust
use const_crypto::{bs58, ed25519, sha2, sha3};

/// Uses const bs58 to roundtrip (decode + encode) system_program ID
pub const PROGRAM_KEY: [u8; 32] = bs58::decode_pubkey("11111111111111111111111111111111");
pub const PROGRAM_KEY_STR: &'static str = bs58::encode_pubkey(&PROGRAM_KEY).str();
const _: () = assert!(ascii_str_eq(
    PROGRAM_KEY_STR,
    "11111111111111111111111111111111"
));

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

/// A utility function used to show round trip is correct
pub const fn ascii_str_eq(a: &str, b: &str) -> bool {
    assert!(a.len() == b.len());
    assert!(a.is_ascii());
    assert!(b.is_ascii());

    let mut i = 0;
    while i < a.len() {
        assert!(a.as_bytes()[i] == b.as_bytes()[i]);
        i += 1
    }
    true
}
```
