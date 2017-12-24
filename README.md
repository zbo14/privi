## rustle

### Pipe

example:

```rust 
use std::fs::File;
use std::io::Cursor;
use sodiumoxide::secretbox::{gen_key,gen_nonce};

pub fn main() {

    // Open file
    let mut file = File::open("test.mp3").unwrap();
    let file_size = file.metadata().unwrap().len() as u32;
    let mime = "audio/mp3".to_owned();

    // New pipe
    let cipher = Cursor::new(Vec::new());
    let mut pipe = Pipe::new(cipher);

    // Encrypt 
    pipe.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime, &mut file).unwrap();
    pipe.cipher.set_position(0);

    // Decrypt
    let mut decrypted = Cursor::new(Vec::new());
    pipe.decrypt(&mut decrypted).unwrap();

    // Read plain bytes
    let mut file = File::open("test.mp3").unwrap();
    let mut plain_bytes = vec![0u8; file_size as usize];
    file.read_exact(&mut plain_bytes).unwrap();

    // Get decrypted bytes
    let decrypted_bytes = decrypted.into_inner();

    // Compare decrypted bytes to plain bytes
    assert_eq!(plain_bytes, decrypted_bytes);
}
```

### Conn

TODO

### Hub 

TODO

