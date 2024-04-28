pub const fn try_from_str(input: &str) -> Result<[u8; 32], &'static str> {
    match decode_pubkey(input.as_bytes()) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(e),
    }
}

pub const fn from_str(input: &str) -> [u8; 32] {
    match try_from_str(input) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            panic!("Invalid base58 Pubkey (Solana & Bitcoin Alphabet)")
        }
    }
}

/// This is const-ified from base58 crate
const fn new(base: &[u8; 58]) -> ([u8; 58], [u8; 128]) {
    let mut encode = [0x00; 58];
    let mut decode = [0xFF; 128];

    let mut i = 0;
    while i < encode.len() {
        encode[i] = base[i];
        decode[base[i] as usize] = i as u8;
        i += 1;
    }

    (encode, decode)
}

/// This is const-ified from base58 crate
///
/// TODO: still need to handle oob w/o panic but like cmon just provide
/// a valid pubkey str
const fn decode_pubkey(input: &[u8]) -> Result<[u8; 32], &'static str> {
    let mut output = [0; 32];

    const ENCODE_DECODE: ([u8; 58], [u8; 128]) = new(&SOLANA_ALPHABET);
    const ENCODE: [u8; 58] = ENCODE_DECODE.0;
    const DECODE: [u8; 128] = ENCODE_DECODE.1;
    const ZERO: u8 = ENCODE[0];

    let mut index = 0;

    let len = input.len();
    let mut i = 0;
    while i < len {
        let c = &input[i];

        if *c > 127 {
            return Err("Input contains non-ASCII");
        }

        let mut val = DECODE[*c as usize] as usize;
        if val == 0xFF {
            return Err("Input contains invalid char");
        }

        let mut inner_idx = 0;
        while inner_idx < index {
            val += (output[inner_idx] as usize) * 58;
            output[inner_idx] = (val & 0xFF) as u8;
            val >>= 8;
            inner_idx += 1;
        }

        while val > 0 {
            output[index] = (val & 0xFF) as u8;
            index += 1;
            val >>= 8;
        }

        i += 1;
    }

    let mut idx = 0;
    while idx < input.len() && input[idx] == ZERO {
        output[index] = 0;
        index += 1;
        idx += 1;
    }

    let mut rev_output = [0; 32];
    let mut idx = 0;
    while idx < 32 {
        rev_output[idx] = output[31 - idx];
        idx += 1;
    }
    Ok(rev_output)
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Base58Str {
    bytes: [u8; 44],
    len: usize,
}

impl Base58Str {
    pub const fn str(&self) -> &str {
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                self.bytes.as_ptr(),
                self.len,
            ))
        }
    }
}

pub const fn encode_pubkey(input: &[u8; 32]) -> Base58Str {
    // Count leading zeros
    let mut in_leading_0s = 0;
    while in_leading_0s < 32 {
        if input[in_leading_0s] != 0 {
            break;
        }
        in_leading_0s += 1;
    }

    let mut binary: [u32; 8] = [0; 8];
    let bytes_as_u32: &[u32] = unsafe {
        // Cast a reference to bytes as a reference to u32
        core::slice::from_raw_parts(
            input.as_ptr() as *const u32,
            input.len() / std::mem::size_of::<u32>(),
        )
    };

    let mut i = 0;
    while i < 8 {
        binary[i] = unsafe { core::ptr::read_unaligned(&bytes_as_u32[i]).to_be() };
        i += 1;
    }

    let mut intermediate: [u64; 9] = [0; 9];

    let mut i = 0;
    while i < 8 {
        let mut j = 0;
        while j < 8 {
            intermediate[j + 1] += binary[i] as u64 * ENC_TABLE_32[i][j];
            j += 1;
        }
        i += 1;
    }

    let mut i = 8;
    while i != 0 {
        intermediate[i - 1] += intermediate[i] / 656_356_768;
        intermediate[i] %= 656_356_768;
        i -= 1
    }

    let mut raw_base58: [u8; 45] = [0; 45];

    let mut i = 0;
    while i < 9 {
        let v = intermediate[i] as u32;
        raw_base58[5 * i + 4] = (v % 58) as u8;
        raw_base58[5 * i + 3] = (v / 58 % 58) as u8;
        raw_base58[5 * i + 2] = (v / 3364 % 58) as u8;
        raw_base58[5 * i + 1] = (v / 195112 % 58) as u8;
        raw_base58[5 * i] = (v / 11316496) as u8;
        i += 1;
    }

    let mut raw_leading_0s = 0;
    while raw_leading_0s < 45 {
        if raw_base58[raw_leading_0s] != 0 {
            break;
        }
        raw_leading_0s += 1;
    }

    let mut out = [0_u8; 44];

    let skip = raw_leading_0s - in_leading_0s;
    let end = 45 - skip;
    let mut i = 0;
    while i != end {
        let idx = raw_base58[skip + i];
        out[i] = SOLANA_ALPHABET[idx as usize];
        i += 1;
    }

    Base58Str {
        bytes: out,
        len: end,
    }
}

const SOLANA_ALPHABET: [u8; 58] = *b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub const ENC_TABLE_32: [[u64; 9 - 1]; 8] = [
    [
        513_735,
        77_223_048,
        437_087_610,
        300_156_666,
        605_448_490,
        214_625_350,
        141_436_834,
        379_377_856,
    ],
    [
        0,
        78_508,
        646_269_101,
        118_408_823,
        91_512_303,
        209_184_527,
        413_102_373,
        153_715_680,
    ],
    [
        0,
        0,
        11_997,
        486_083_817,
        3_737_691,
        294_005_210,
        247_894_721,
        289_024_608,
    ],
    [
        0,
        0,
        0,
        1_833,
        324_463_681,
        385_795_061,
        551_597_588,
        21_339_008,
    ],
    [0, 0, 0, 0, 280, 127_692_781, 389_432_875, 357_132_832],
    [0, 0, 0, 0, 0, 42, 537_767_569, 410_450_016],
    [0, 0, 0, 0, 0, 0, 6, 356_826_688],
    [0, 0, 0, 0, 0, 0, 0, 1],
];

/// This case is tested explicitly because the initial implementation
/// had an out-of-bounds access that panicked for this case (system_program ID)
#[test]
fn test_null_case_round_trip() {
    let bytes = [0; 32];
    let encoded = bs58::encode(bytes).into_string();
    assert_eq!(from_str(&encoded), bytes);
}

#[test]
fn test_many_random() {
    for _ in 0..100_000 {
        // Generate random bytes
        let bytes = rand::random::<[u8; 32]>();

        // Encode using bs58 crate
        let encoded = bs58::encode(bytes).into_string();

        // Check our decoded impl matches original bytes
        assert_eq!(from_str(&encoded), bytes);
    }
}

#[test]
fn test_encode() {
    for _ in 0..100_000 {
        // Generate random bytes
        let bytes = rand::random::<[u8; 32]>();

        // Encode using bs58 crate
        let encoded = bs58::encode(bytes).into_string();

        // Check our encoded impl matches original bytes
        assert_eq!(encoded, encode_pubkey(&bytes).str());
    }
}
