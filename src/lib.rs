pub struct ConstCiphers {}

pub enum CipherMode<const AAD_LEN: usize> {
    ECB,
    CBC { iv: [u8; 16] },
    GCM { iv: [u8; 12], aad: [u8; AAD_LEN] },
}

impl ConstCiphers {
    /// `const` AES-128 encryption function.
    ///
    /// # Parameters
    ///
    /// - `plaintext`: Reference to a byte array to be encrypted (16 bytes).
    /// - `key`: Reference to a byte array used as the encryption key (16 bytes).
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 16])`: Encrypted byte array.
    /// - `Err(&'static str)`: Error message if the key or plaintext length is incorrect.
    pub const fn aes_encrypt(plaintext: &[u8; 16], key: &[u8; 16]) -> Result<[u8; 16], &'static str> {
        // Step 1: Key Expansion
        let round_keys = match Self::key_expansion(key) {
            Some(k) => k,
            None => return Err("Key expansion failed"),
        };

        // Step 2: Initial AddRoundKey
        let mut state = Self::add_round_key(plaintext, &round_keys[0]);

        // Steps 3-9: 9 Rounds
        let mut round = 1;
        while round < 10 {
            state = Self::sub_bytes(&state);
            state = Self::shift_rows(&state);
            state = Self::mix_columns(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            round += 1;
        }

        // Step 10: Final Round (without MixColumns)
        state = Self::sub_bytes(&state);
        state = Self::shift_rows(&state);
        state = Self::add_round_key(&state, &round_keys[10]);

        Ok(state)
    }

    /// `const` AES-128 decryption function.
    ///
    /// # Parameters
    ///
    /// - `ciphertext`: Reference to a byte array to be decrypted (16 bytes).
    /// - `key`: Reference to a byte array used as the decryption key (16 bytes).
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 16])`: Decrypted byte array.
    /// - `Err(&'static str)`: Error message if the key or ciphertext length is incorrect.
    pub const fn aes_decrypt(ciphertext: &[u8; 16], key: &[u8; 16]) -> Result<[u8; 16], &'static str> {
        // Step 1: Key Expansion
        let round_keys = match Self::key_expansion(key) {
            Some(k) => k,
            None => return Err("Key expansion failed"),
        };

        // Step 2: Initial AddRoundKey
        let mut state = Self::add_round_key(ciphertext, &round_keys[10]);

        // Steps 3-9: 9 Rounds
        let mut round = 9;
        while round > 0 {
            state = Self::inv_shift_rows(&state);
            state = Self::inv_sub_bytes(&state);
            state = Self::add_round_key(&state, &round_keys[round]);
            state = Self::inv_mix_columns(&state);
            round -= 1;
        }

        // Step 10: Final Round (without InvMixColumns)
        state = Self::inv_shift_rows(&state);
        state = Self::inv_sub_bytes(&state);
        state = Self::add_round_key(&state, &round_keys[0]);

        Ok(state)
    }

    const SBOX: [u8; 256] = [
        // 0     1    2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, //F
    ];

    const INV_SBOX: [u8; 256] = [
        // 0     1    2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, //F
    ];

    const RCON: [u8; 11] = [
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
    ];

    const fn key_expansion(key: &[u8; 16]) -> Option<[[u8; 16]; 11]> {
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

        Some(round_keys)
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

            new_state[i] = Self::gf_mul(s0, 14) ^ Self::gf_mul(s1, 11) ^ Self::gf_mul(s2, 13) ^ Self::gf_mul(s3, 9);
            new_state[i + 1] = Self::gf_mul(s0, 9) ^ Self::gf_mul(s1, 14) ^ Self::gf_mul(s2, 11) ^ Self::gf_mul(s3, 13);
            new_state[i + 2] = Self::gf_mul(s0, 13) ^ Self::gf_mul(s1, 9) ^ Self::gf_mul(s2, 14) ^ Self::gf_mul(s3, 11);
            new_state[i + 3] = Self::gf_mul(s0, 11) ^ Self::gf_mul(s1, 13) ^ Self::gf_mul(s2, 9) ^ Self::gf_mul(s3, 14);

            i += 4;
        }
        new_state
    }
}

#[cfg(test)]
mod tests {
    use super::ConstCiphers;

    #[test]
    fn test_aes_encrypt_decrypt_identity() {
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x54, 0x99, 0x09, 0xcf, 0x4f, 0x3c,
        ];

        let encrypted = ConstCiphers::aes_encrypt(&plaintext, &key)
            .expect("Encryption failed");

        let decrypted = ConstCiphers::aes_decrypt(&encrypted, &key)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext, "Decrypted text does not match original plaintext");
    }

    #[test]
    fn test_aes_encrypt_decrypt_all_zeros() {
        let plaintext = [0u8; 16];
        let key = [0u8; 16];

        let encrypted = ConstCiphers::aes_encrypt(&plaintext, &key)
            .expect("Encryption failed");
        let decrypted = ConstCiphers::aes_decrypt(&encrypted, &key)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext, "All-zeros test failed");
    }

    #[test]
    fn test_aes_encrypt_decrypt_all_ones() {
        let plaintext = [0xFFu8; 16];
        let key = [0xFFu8; 16];

        let encrypted = ConstCiphers::aes_encrypt(&plaintext, &key)
            .expect("Encryption failed");
        let decrypted = ConstCiphers::aes_decrypt(&encrypted, &key)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext, "All-ones test failed");
    }
}
