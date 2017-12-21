## rustle

example:

```rust 
use std::fs::File;
use std::io::Cursor;
use sodiumoxide::secretbox::xsalsa20poly1305::{gen_key,gen_nonce};

pub fn main() {

	// Generate key
	let key = gen_key();

	// Generate nonce 
	let nonce = gen_nonce();

	// Open file 
	let mut source = File::open("test.mp3").unwrap();

	// File mimetype and size 
	let file_size = source.metadata().unwrap().len() as u32;
	let mime = "audio/mp3".to_owned();

	// Destinations
	let mut dest1 = Cursor::new(Vec::new());
	let mut dest2 = Cursor::new(Vec::new());

	{
		// Encrypt 
		let mut pipe1 = Pipe::new(&key, &nonce, &mut source, &mut dest1);
		pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime).unwrap();
		pipe1.dest.set_position(0);

		// Decrypt
		let mut pipe2 = Pipe::new(&key, &nonce, &mut pipe1, &mut dest2);
		pipe2.decrypt().unwrap();
		pipe2.dest.set_position(0);
	}

	// Read plain bytes
	let mut file = File::open("./test.mp3").unwrap();
	let mut plain_bytes = vec![0u8; file_size as usize];
	file.read_exact(&mut plain_bytes).unwrap();

	// Get decrypted bytes
	let decrypted_bytes = dest2.into_inner();

	// Compare decrypted bytes to plain bytes
	assert_eq!(plain_bytes, decrypted_bytes);	
}
```

