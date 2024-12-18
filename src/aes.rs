use const_for::const_for;

pub enum AesMode {
    ECB,
    CBC { iv: [u8; 16] },
    CTR { iv: [u8; 12] },
}

pub struct AesConst {}

impl AesConst {
    pub fn encrypt<const N: usize>(plaintext: &[u8; N], key: &[u8; 16], mode: &AesMode) -> [u8; N] {
        match mode {
            AesMode::ECB => Self::encrypt_ecb(plaintext, key),
            AesMode::CBC { iv } => Self::encrypt_cbc(plaintext, key, iv),
            AesMode::CTR { iv } => Self::encrypt_ctr(plaintext, key, iv),
        }
    }

    pub const fn decrypt<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        mode: &AesMode,
    ) -> [u8; N] {
        match mode {
            AesMode::ECB => Self::decrypt_ecb(ciphertext, key),
            AesMode::CBC { iv } => Self::decrypt_cbc(ciphertext, key, iv),
            AesMode::CTR { iv } => Self::decrypt_ctr(ciphertext, key, iv),
        }
    }

    pub const fn encrypt_block(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let round_keys = Self::key_expansion(key);
        let mut state = Self::add_round_key(plaintext, &round_keys[0]);

        let mut round = 1;
        while round < 10 {
            state = Self::sub_bytes(&state);
            state = Self::shift_rows(&state);
            state = Self::mix_columns(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            round += 1;
        }

        state = Self::sub_bytes(&state);
        state = Self::shift_rows(&state);
        state = Self::add_round_key(&state, &round_keys[10]);

        state
    }

    pub const fn decrypt_block(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let round_keys = Self::key_expansion(key);
        let mut state = Self::add_round_key(ciphertext, &round_keys[10]);

        let mut round = 9;
        while round > 0 {
            state = Self::inv_shift_rows(&state);
            state = Self::inv_sub_bytes(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            state = Self::inv_mix_columns(&state);
            round -= 1;
        }

        state = Self::inv_shift_rows(&state);
        state = Self::inv_sub_bytes(&state);
        state = Self::add_round_key(&state, &round_keys[0]);

        state
    }

    const fn encrypt_ecb<const N: usize>(plaintext: &[u8; N], key: &[u8; 16]) -> [u8; N] {
        let mut result = [0u8; N];
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = plaintext[i + j];
                j += 1;
            }

            let enc_block = Self::encrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = enc_block[j];
                j += 1;
            }
            i += 16;
        }
        result
    }

    const fn decrypt_ecb<const N: usize>(ciphertext: &[u8; N], key: &[u8; 16]) -> [u8; N] {
        if N % 16 != 0 {
            panic!("Invalid ciphertext length for ECB.");
        }

        let mut result = [0u8; N];
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = ciphertext[i + j];
                j += 1;
            }

            let dec_block = Self::decrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = dec_block[j];
                j += 1;
            }
            i += 16;
        }
        result
    }

    const fn encrypt_cbc<const N: usize>(
        plaintext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> [u8; N] {
        if N % 16 != 0 {
            panic!("Invalid plaintext length for CBC.");
        }

        let mut result = [0u8; N];
        let mut prev = *iv;
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = plaintext[i + j] ^ prev[j];
                j += 1;
            }

            let enc_block = Self::encrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = enc_block[j];
                j += 1;
            }

            prev = enc_block;
            i += 16;
        }
        result
    }

    const fn decrypt_cbc<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> [u8; N] {
        let mut result = [0u8; N];
        let mut prev = *iv;
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = ciphertext[i + j];
                j += 1;
            }

            let dec_block = Self::decrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = dec_block[j] ^ prev[j];
                j += 1;
            }

            prev = block;
            i += 16;
        }
        result
    }

    const fn encrypt_ctr<const N: usize>(
        plaintext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 12],
    ) -> [u8; N] {
        let mut ciphertext = [0u8; N];
        let mut counter = Self::ctr_init(iv);

        let mut i = 0;
        while i < N {
            let keystream = Self::encrypt_block(&counter, key);
            let block_size = if i + 16 > N { N - i } else { 16 };
            const_for!(j in 0..block_size => {
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            });
            counter = Self::ctr_increment(&counter);
            i += 16;
        }

        ciphertext
    }

    const fn decrypt_ctr<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 12],
    ) -> [u8; N] {
        // CTR decryption is identical to encryption
        Self::encrypt_ctr(ciphertext, key, iv)
    }

    const fn ctr_init(iv: &[u8; 12]) -> [u8; 16] {
        let mut counter = [0u8; 16];
        let mut i = 0;
        while i < 12 {
            counter[i] = iv[i];
            i += 1;
        }
        counter[15] = 1;
        counter
    }

    const fn ctr_increment(counter: &[u8; 16]) -> [u8; 16] {
        let mut new_counter = *counter;
        let mut i = 15;
        while i >= 12 {
            if new_counter[i] == 255 {
                new_counter[i] = 0;
                if i == 12 {
                    break;
                }
                i -= 1;
            } else {
                new_counter[i] += 1;
                break;
            }
        }
        new_counter
    }

    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    const RCON: [u8; 11] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
    ];

    const fn key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
        let mut round_keys = [[0u8; 16]; 11];
        let mut i = 0;

        let mut j = 0;
        while j < 16 {
            round_keys[0][j] = key[j];
            j += 1;
        }

        while i < 10 {
            let mut t = [0u8; 4];
            t[0] = round_keys[i][12];
            t[1] = round_keys[i][13];
            t[2] = round_keys[i][14];
            t[3] = round_keys[i][15];

            t = [t[1], t[2], t[3], t[0]];

            let mut k = 0;
            while k < 4 {
                t[k] = Self::sbox(t[k]);
                k += 1;
            }

            t[0] ^= Self::RCON[i + 1];

            let mut m = 0;
            while m < 4 {
                round_keys[i + 1][m] = round_keys[i][m] ^ t[m];
                m += 1;
            }

            let mut n = 4;
            while n < 16 {
                round_keys[i + 1][n] = round_keys[i + 1][n - 4] ^ round_keys[i][n];
                n += 1;
            }

            i += 1;
        }

        round_keys
    }

    const fn sbox(byte: u8) -> u8 {
        Self::SBOX[byte as usize]
    }

    const fn inv_sbox(byte: u8) -> u8 {
        Self::INV_SBOX[byte as usize]
    }

    const fn add_round_key(state: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = state[i] ^ round_key[i];
            i += 1;
        }
        new_state
    }

    const fn sub_bytes(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = Self::sbox(state[i]);
            i += 1;
        }
        new_state
    }

    const fn inv_sub_bytes(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = Self::inv_sbox(state[i]);
            i += 1;
        }
        new_state
    }

    const fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        new_state[0] = state[0];
        new_state[4] = state[4];
        new_state[8] = state[8];
        new_state[12] = state[12];

        new_state[1] = state[5];
        new_state[5] = state[9];
        new_state[9] = state[13];
        new_state[13] = state[1];

        new_state[2] = state[10];
        new_state[6] = state[14];
        new_state[10] = state[2];
        new_state[14] = state[6];

        new_state[3] = state[15];
        new_state[7] = state[3];
        new_state[11] = state[7];
        new_state[15] = state[11];

        new_state
    }

    const fn inv_shift_rows(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        new_state[0] = state[0];
        new_state[4] = state[4];
        new_state[8] = state[8];
        new_state[12] = state[12];

        new_state[1] = state[13];
        new_state[5] = state[1];
        new_state[9] = state[5];
        new_state[13] = state[9];

        new_state[2] = state[10];
        new_state[6] = state[14];
        new_state[10] = state[2];
        new_state[14] = state[6];

        new_state[3] = state[7];
        new_state[7] = state[11];
        new_state[11] = state[15];
        new_state[15] = state[3];

        new_state
    }

    const fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0;
        let mut a = a;
        let mut b = b;
        let mut i = 0;
        while i < 8 {
            if (b & 1) != 0 {
                result ^= a;
            }
            let high_bit = (a & 0x80) != 0;
            a <<= 1;
            if high_bit {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }
        result
    }

    const fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            new_state[i] = Self::gf_mul(s0, 2) ^ Self::gf_mul(s1, 3) ^ s2 ^ s3;
            new_state[i + 1] = s0 ^ Self::gf_mul(s1, 2) ^ Self::gf_mul(s2, 3) ^ s3;
            new_state[i + 2] = s0 ^ s1 ^ Self::gf_mul(s2, 2) ^ Self::gf_mul(s3, 3);
            new_state[i + 3] = Self::gf_mul(s0, 3) ^ s1 ^ s2 ^ Self::gf_mul(s3, 2);

            i += 4;
        }
        new_state
    }

    const fn inv_mix_columns(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            new_state[i] = Self::gf_mul(s0, 14)
                ^ Self::gf_mul(s1, 11)
                ^ Self::gf_mul(s2, 13)
                ^ Self::gf_mul(s3, 9);
            new_state[i + 1] = Self::gf_mul(s0, 9)
                ^ Self::gf_mul(s1, 14)
                ^ Self::gf_mul(s2, 11)
                ^ Self::gf_mul(s3, 13);
            new_state[i + 2] = Self::gf_mul(s0, 13)
                ^ Self::gf_mul(s1, 9)
                ^ Self::gf_mul(s2, 14)
                ^ Self::gf_mul(s3, 11);
            new_state[i + 3] = Self::gf_mul(s0, 11)
                ^ Self::gf_mul(s1, 13)
                ^ Self::gf_mul(s2, 9)
                ^ Self::gf_mul(s3, 14);

            i += 4;
        }
        new_state
    }
}

pub struct Aes {}

impl Aes {
    pub fn encrypt<const N: usize>(plaintext: &[u8; N], key: &[u8; 16], mode: &AesMode) -> [u8; N] {
        match mode {
            AesMode::ECB => Self::encrypt_ecb(plaintext, key),
            AesMode::CBC { iv } => Self::encrypt_cbc(plaintext, key, iv),
            AesMode::CTR { iv } => Self::encrypt_ctr(plaintext, key, iv),
        }
    }

    pub fn decrypt<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        mode: &AesMode,
    ) -> [u8; N] {
        match mode {
            AesMode::ECB => Self::decrypt_ecb(ciphertext, key),
            AesMode::CBC { iv } => Self::decrypt_cbc(ciphertext, key, iv),
            AesMode::CTR { iv } => Self::decrypt_ctr(ciphertext, key, iv),
        }
    }

    pub fn encrypt_block(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let round_keys = Self::key_expansion(key);
        let mut state = Self::add_round_key(plaintext, &round_keys[0]);

        let mut round = 1;
        while round < 10 {
            state = Self::sub_bytes(&state);
            state = Self::shift_rows(&state);
            state = Self::mix_columns(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            round += 1;
        }

        state = Self::sub_bytes(&state);
        state = Self::shift_rows(&state);
        state = Self::add_round_key(&state, &round_keys[10]);

        state
    }

    pub fn decrypt_block(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let round_keys = Self::key_expansion(key);
        let mut state = Self::add_round_key(ciphertext, &round_keys[10]);

        let mut round = 9;
        while round > 0 {
            state = Self::inv_shift_rows(&state);
            state = Self::inv_sub_bytes(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            state = Self::inv_mix_columns(&state);
            round -= 1;
        }

        state = Self::inv_shift_rows(&state);
        state = Self::inv_sub_bytes(&state);
        state = Self::add_round_key(&state, &round_keys[0]);

        state
    }

    fn encrypt_ecb<const N: usize>(plaintext: &[u8; N], key: &[u8; 16]) -> [u8; N] {
        let mut result = [0u8; N];
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = plaintext[i + j];
                j += 1;
            }

            let enc_block = Self::encrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = enc_block[j];
                j += 1;
            }
            i += 16;
        }
        result
    }

    fn decrypt_ecb<const N: usize>(ciphertext: &[u8; N], key: &[u8; 16]) -> [u8; N] {
        if N % 16 != 0 {
            panic!("Invalid ciphertext length for ECB.");
        }

        let mut result = [0u8; N];
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = ciphertext[i + j];
                j += 1;
            }

            let dec_block = Self::decrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = dec_block[j];
                j += 1;
            }
            i += 16;
        }
        result
    }

    fn encrypt_cbc<const N: usize>(
        plaintext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> [u8; N] {
        if N % 16 != 0 {
            panic!("Invalid plaintext length for CBC.");
        }

        let mut result = [0u8; N];
        let mut prev = *iv;
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = plaintext[i + j] ^ prev[j];
                j += 1;
            }

            let enc_block = Self::encrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = enc_block[j];
                j += 1;
            }

            prev = enc_block;
            i += 16;
        }
        result
    }

    fn decrypt_cbc<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> [u8; N] {
        let mut result = [0u8; N];
        let mut prev = *iv;
        let mut i = 0;
        while i < N {
            let mut block = [0u8; 16];
            let mut j = 0;
            while j < 16 {
                block[j] = ciphertext[i + j];
                j += 1;
            }

            let dec_block = Self::decrypt_block(&block, key);

            j = 0;
            while j < 16 {
                result[i + j] = dec_block[j] ^ prev[j];
                j += 1;
            }

            prev = block;
            i += 16;
        }
        result
    }

    fn encrypt_ctr<const N: usize>(
        plaintext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 12],
    ) -> [u8; N] {
        let mut ciphertext = [0u8; N];
        let mut counter = Self::ctr_init(iv);

        let mut i = 0;
        while i < N {
            let keystream = Self::encrypt_block(&counter, key);
            let block_size = if i + 16 > N { N - i } else { 16 };
            const_for!(j in 0..block_size => {
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            });
            counter = Self::ctr_increment(&counter);
            i += 16;
        }

        ciphertext
    }

    fn decrypt_ctr<const N: usize>(
        ciphertext: &[u8; N],
        key: &[u8; 16],
        iv: &[u8; 12],
    ) -> [u8; N] {
        // CTR decryption is identical to encryption
        Self::encrypt_ctr(ciphertext, key, iv)
    }

    fn ctr_init(iv: &[u8; 12]) -> [u8; 16] {
        let mut counter = [0u8; 16];
        let mut i = 0;
        while i < 12 {
            counter[i] = iv[i];
            i += 1;
        }
        counter[15] = 1;
        counter
    }

    fn ctr_increment(counter: &[u8; 16]) -> [u8; 16] {
        let mut new_counter = *counter;
        let mut i = 15;
        while i >= 12 {
            if new_counter[i] == 255 {
                new_counter[i] = 0;
                if i == 12 {
                    break;
                }
                i -= 1;
            } else {
                new_counter[i] += 1;
                break;
            }
        }
        new_counter
    }

    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    const RCON: [u8; 11] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
    ];

    fn key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
        let mut round_keys = [[0u8; 16]; 11];
        let mut i = 0;

        let mut j = 0;
        while j < 16 {
            round_keys[0][j] = key[j];
            j += 1;
        }

        while i < 10 {
            let mut t = [0u8; 4];
            t[0] = round_keys[i][12];
            t[1] = round_keys[i][13];
            t[2] = round_keys[i][14];
            t[3] = round_keys[i][15];

            t = [t[1], t[2], t[3], t[0]];

            let mut k = 0;
            while k < 4 {
                t[k] = Self::sbox(t[k]);
                k += 1;
            }

            t[0] ^= Self::RCON[i + 1];

            let mut m = 0;
            while m < 4 {
                round_keys[i + 1][m] = round_keys[i][m] ^ t[m];
                m += 1;
            }

            let mut n = 4;
            while n < 16 {
                round_keys[i + 1][n] = round_keys[i + 1][n - 4] ^ round_keys[i][n];
                n += 1;
            }

            i += 1;
        }

        round_keys
    }

    fn sbox(byte: u8) -> u8 {
        Self::SBOX[byte as usize]
    }

    fn inv_sbox(byte: u8) -> u8 {
        Self::INV_SBOX[byte as usize]
    }

    fn add_round_key(state: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = state[i] ^ round_key[i];
            i += 1;
        }
        new_state
    }

    fn sub_bytes(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = Self::sbox(state[i]);
            i += 1;
        }
        new_state
    }

    fn inv_sub_bytes(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            new_state[i] = Self::inv_sbox(state[i]);
            i += 1;
        }
        new_state
    }

    fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        new_state[0] = state[0];
        new_state[4] = state[4];
        new_state[8] = state[8];
        new_state[12] = state[12];

        new_state[1] = state[5];
        new_state[5] = state[9];
        new_state[9] = state[13];
        new_state[13] = state[1];

        new_state[2] = state[10];
        new_state[6] = state[14];
        new_state[10] = state[2];
        new_state[14] = state[6];

        new_state[3] = state[15];
        new_state[7] = state[3];
        new_state[11] = state[7];
        new_state[15] = state[11];

        new_state
    }

    fn inv_shift_rows(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        new_state[0] = state[0];
        new_state[4] = state[4];
        new_state[8] = state[8];
        new_state[12] = state[12];

        new_state[1] = state[13];
        new_state[5] = state[1];
        new_state[9] = state[5];
        new_state[13] = state[9];

        new_state[2] = state[10];
        new_state[6] = state[14];
        new_state[10] = state[2];
        new_state[14] = state[6];

        new_state[3] = state[7];
        new_state[7] = state[11];
        new_state[11] = state[15];
        new_state[15] = state[3];

        new_state
    }

    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0;
        let mut a = a;
        let mut b = b;
        let mut i = 0;
        while i < 8 {
            if (b & 1) != 0 {
                result ^= a;
            }
            let high_bit = (a & 0x80) != 0;
            a <<= 1;
            if high_bit {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }
        result
    }

    fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            new_state[i] = Self::gf_mul(s0, 2) ^ Self::gf_mul(s1, 3) ^ s2 ^ s3;
            new_state[i + 1] = s0 ^ Self::gf_mul(s1, 2) ^ Self::gf_mul(s2, 3) ^ s3;
            new_state[i + 2] = s0 ^ s1 ^ Self::gf_mul(s2, 2) ^ Self::gf_mul(s3, 3);
            new_state[i + 3] = Self::gf_mul(s0, 3) ^ s1 ^ s2 ^ Self::gf_mul(s3, 2);

            i += 4;
        }
        new_state
    }

    fn inv_mix_columns(state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            new_state[i] = Self::gf_mul(s0, 14)
                ^ Self::gf_mul(s1, 11)
                ^ Self::gf_mul(s2, 13)
                ^ Self::gf_mul(s3, 9);
            new_state[i + 1] = Self::gf_mul(s0, 9)
                ^ Self::gf_mul(s1, 14)
                ^ Self::gf_mul(s2, 11)
                ^ Self::gf_mul(s3, 13);
            new_state[i + 2] = Self::gf_mul(s0, 13)
                ^ Self::gf_mul(s1, 9)
                ^ Self::gf_mul(s2, 14)
                ^ Self::gf_mul(s3, 11);
            new_state[i + 3] = Self::gf_mul(s0, 11)
                ^ Self::gf_mul(s1, 13)
                ^ Self::gf_mul(s2, 9)
                ^ Self::gf_mul(s3, 14);

            i += 4;
        }
        new_state
    }
}

#[cfg(test)]
mod tests {
    use super::{AesConst, AesMode};

    #[test]
    fn test_csingle_block_mode() {
        let plaintext = [0u8; 16];
        let key = [0xFF; 16];

        let ciphertext = AesConst::encrypt_block(&plaintext, &key);
        let decrypted = AesConst::decrypt_block(&ciphertext, &key);

        assert_eq!(decrypted, plaintext, "Single block mode test failed");
    }

    #[test]
    fn test_const_ecb_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let mode = AesMode::ECB {};

        let ciphertext = AesConst::encrypt(&plaintext, &key, &mode);
        let decrypted = AesConst::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "ECB mode test failed");
    }

    #[test]
    fn test_const_cbc_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let iv = [0x00; 16];
        let mode = AesMode::CBC { iv };

        let ciphertext = AesConst::encrypt(&plaintext, &key, &mode);
        let decrypted = AesConst::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "CBC mode test failed");
    }

    #[test]
    fn test_const_ctr_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let iv = [0x00; 12];
        let mode = AesMode::CTR { iv };

        let ciphertext = AesConst::encrypt(&plaintext, &key, &mode);
        let decrypted = AesConst::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "CTR mode test failed");
    }

    use super::Aes;

    #[test]
    fn test_nonconst_single_block_mode() {
        let plaintext = [0u8; 16];
        let key = [0xFF; 16];

        let ciphertext = Aes::encrypt_block(&plaintext, &key);
        let decrypted = Aes::decrypt_block(&ciphertext, &key);

        assert_eq!(decrypted, plaintext, "Single block mode test failed");
    }

    #[test]
    fn test_nonconst_ecb_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let mode = AesMode::ECB {};

        let ciphertext = Aes::encrypt(&plaintext, &key, &mode);
        let decrypted = Aes::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "ECB mode test failed");
    }

    #[test]
    fn test_nonconst_cbc_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let iv = [0x00; 16];
        let mode = AesMode::CBC { iv };

        let ciphertext = Aes::encrypt(&plaintext, &key, &mode);
        let decrypted = Aes::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "CBC mode test failed");
    }

    #[test]
    fn test_nonconst_ctr_mode() {
        let plaintext = [0u8; 32];
        let key = [0xFF; 16];
        let iv = [0x00; 12];
        let mode = AesMode::CTR { iv };

        let ciphertext = Aes::encrypt(&plaintext, &key, &mode);
        let decrypted = Aes::decrypt(&ciphertext, &key, &mode);

        assert_eq!(decrypted, plaintext, "CTR mode test failed");
    }
}