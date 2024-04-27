#![allow(long_running_const_eval)]

use solana_sdk::pubkey::Pubkey;

pub mod const_bs58;
pub mod crypto;

pub const PROGRAM_CONFIG_SEED: &'static [u8] = b"program_config";
pub const PROGRAM_KEY: [u8; 32] = const_bs58::from_str(
    "2EtTPozZVhEujp31QhpA5aoPv78epBCPhFKmDeTZCdtx",
);

pub const PROGRAM_AUTHORITY_ADDRESS_AND_BUMP: ([u8; 32], u8) =
    crypto::derive_program_address(
        &[PROGRAM_CONFIG_SEED],
        &PROGRAM_KEY,
    );

pub const PROGRAM_AUTHORITY_ADDRESS: Pubkey =
    Pubkey::new_from_array(PROGRAM_AUTHORITY_ADDRESS_AND_BUMP.0);
pub const PROGRAM_AUTHORITY_BUMP: u8 =
    PROGRAM_AUTHORITY_ADDRESS_AND_BUMP.1;
