# Const ciphers

## Installation

```bash
cargo add const-ciphers
```

## Usage

```
use const-ciphers::{AesConst, AesMode};

const fn example() {
    let plaintext = [0u8; 32];
    let key = [0xFF; 16];
    let iv = [0x00; 16];
    let mode = AesMode::CBC { iv };

    let encrypted = AesConst::encrypt(&plaintext, &key, &mode);
    let decrypted = AesConst::decrypt(&encrypted, &key, &mode);
}
```

> [!CAUTION]
> Not for cryptographic use. No cryptographic properties guaranteed. Only use for payload generation.