use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use std::io::{self, Write};

fn prompt_hex(label: &str) -> Vec<u8> {
    loop {
        print!("{label} (hex): ");
        io::stdout().flush().unwrap(); //Prompts user with parameter to be filled

        let mut line = String::new(); //Reads line from typed prompt into line
        io::stdin()
            .read_line(&mut line)
            .expect("failed to read input");

        let cleaned: String = line.chars().filter(|c| !c.is_whitespace()).collect(); //cleanses 0x and prefixes
        let cleaned = cleaned.strip_prefix("0x").unwrap_or(cleaned.as_str());

        match hex::decode(cleaned) {
            Ok(bytes) => return bytes,
            Err(e) => println!("Invalid hex: {e}. Try again."),
        }
    }
}

fn decrypt<D>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String>
//Parameters needed
where
    D: KeyIvInit + BlockDecryptMut, //Combines both functions, allows us to call D for methods belonging to both
{
    let cipher = D::new_from_slices(key, iv)
        .map_err(|_| "invalid key or IV length (IV must be 16 bytes)".to_string())?; //IV must be 16 bytes, acts as the initialization vector that XOR Plaintext
    cipher.decrypt_padded_vec_mut::<NoPadding>(ct).map_err(|_| {
        "decryption failed: bad padding (wrong key/IV?) or length not a multiple of 16".to_string()
    })
}

fn main() {
    let key = prompt_hex("Key");
    let iv = prompt_hex("IV");
    let ciphertext = prompt_hex("Ciphertext");

    let result = match key.len() {
        16 => decrypt::<cbc::Decryptor<Aes128>>(&key, &iv, &ciphertext),
        24 => decrypt::<cbc::Decryptor<Aes192>>(&key, &iv, &ciphertext),
        32 => decrypt::<cbc::Decryptor<Aes256>>(&key, &iv, &ciphertext),
        n => Err(format!("key must be 16, 24, or 32 bytes, got {n}")),
    };

    match result {
        Ok(plaintext) => {
            println!("Raw bytes: {}", hex::encode(&plaintext)); //& borrows value, can be parameterized multiple times
            println!("As text:   {}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
