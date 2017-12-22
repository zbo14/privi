## rustle

example:

```rust 
use std::fs::File;
use std::io::Cursor;
use sodiumoxide::secretbox::{gen_key,gen_nonce};

fn main() {

    // Generate key and nonce
    let key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();

    let mut cipher = Cursor::new(Vec::new());
    let mut plain = File::open("test.mp3").unwrap();
    let mut decrypted = Cursor::new(Vec::new());

    // File mimetype and size 
    let file_size = plain.metadata().unwrap().len() as u32;
    let mime = "audio/mp3".to_owned();

    {
        // Encrypt 
        let mut pipe1 = Pipe::new(&mut cipher, key.clone(), nonce.clone());
        pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime, &mut plain).unwrap();
        pipe1.cipher.set_position(0);
    }

    {
        // Decrypt
        let mut pipe2 = Pipe::new(&mut cipher, key, nonce);
        pipe2.decrypt(&mut decrypted).unwrap();
    }

    // Read plain bytes
    let mut plain = File::open("test.mp3").unwrap();
    let mut plain_bytes = vec![0u8; file_size as usize];
    plain.read_exact(&mut plain_bytes).unwrap();

    // Get decrypted bytes
    let decrypted_bytes = decrypted.into_inner();

    // Compare decrypted bytes to plain bytes
    assert_eq!(plain_bytes, decrypted_bytes);
}
```

