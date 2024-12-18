use const_for::const_for;

pub struct Rc4Const {}

impl Rc4Const {
    pub const fn encrypt<const N: usize, const K: usize>(
        plaintext: &[u8; N],
        key: &[u8; K],
    ) -> [u8; N] {
        if K == 0 {
            panic!("Key cannot be empty");
        }

        let mut s = [0u8; 256];
        const_for!(i in 0..256 => {
            s[i] = i as u8;
        });

        let mut j = 0usize;
        const_for!(i in 0..256 => {
            j = (j + s[i] as usize + key[i % K] as usize) % 256;

            // Manual swap
            let tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        });

        let mut i = 0usize;
        j = 0usize;
        let mut ciphertext = [0u8; N];

        const_for!(n in 0..N => {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;

            // Manual swap
            let tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;

            let k = s[(s[i] as usize + s[j] as usize) % 256];
            ciphertext[n] = plaintext[n] ^ k;
        });

        ciphertext
    }

    pub const fn decrypt<const N: usize, const K: usize>(
        ciphertext: &[u8; N],
        key: &[u8; K],
    ) -> [u8; N] {
        Self::encrypt(ciphertext, key)
    }
}

#[cfg(test)]
mod tests {
    use crate::rc4::Rc4Const;

    #[test]
    fn test_block_mode() {
        let plaintext = [0u8; 16];
        let key = [0xFF; 16];

        let encrypted = Rc4Const::encrypt(&plaintext, &key);
        let decrypted = Rc4Const::decrypt(&encrypted, &key);

        assert_eq!(
            decrypted, plaintext,
            "Decrypted text does not match original plaintext"
        );
    }
}
