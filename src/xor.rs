use const_for::const_for;

pub struct XorConst {}

impl XorConst {
    pub const fn encrypt<const N: usize, const K: usize>(
        plaintext: &[u8; N],
        key: &[u8; K],
    ) -> [u8; N] {
        if K == 0 {
            panic!("Key cannot be empty");
        }

        let mut ciphertext = [0u8; N];
        const_for!(i in 0..N => {
            ciphertext[i] = plaintext[i] ^ key[i % K];
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
    use crate::xor::XorConst;

    #[test]
    fn test() {
        let plaintext = [0u8; 16];
        let key = [0xFF; 16];

        let encrypted = XorConst::encrypt(&plaintext, &key);
        let decrypted = XorConst::decrypt(&encrypted, &key);

        assert_eq!(
            decrypted, plaintext,
            "Decrypted text does not match original plaintext"
        );
    }
}
