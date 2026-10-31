# AES-CBC Decryptor

Rust Program that takes an a key (16, 24, or 32 characters), IV (16 bytes), and ciphertext and decrypts in AES-CBC

Runs for the following padding methods:
ansi-x923
iso7816
no-padding
-pkcs7
zero-padding

## Usage

```
cargo run -p cbc-pkcs7
```

Example (PKCS7-padded):

```
Key (hex):        2b7e151628aed2a6abf7158809cf4f3c
IV (hex):         000102030405060708090a0b0c0d0e0f
Ciphertext (hex): a179a31c028299c0c4a301847e8e3d92d03ad1185b9f225596da1b4e351cda78
```

Output: `hello world, this is CBC`

Note that each padding method should use the same key and iv. Padding only affects what gets appended to the plaintext.
