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

    const SOLANA_ALPHABET: [u8; 58] =
        *b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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

    // let mut idx = 0;
    // let mut c = input[idx];
    // while c == ZERO {
    //     c = input[idx];
    //     idx += 1;

    //     output[index] = 0;
    //     index += 1;
    // }

    // let mut idx = 0;
    // let mut c = input[idx];
    // while c == ZERO && idx < input.len() {
    //     idx += 1;
    //     if idx < input.len() {
    //         c = input[idx];
    //     }

    //     output[index] = 0;
    //     index += 1;
    // }

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
