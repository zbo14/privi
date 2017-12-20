## rustle

example:

```rust 
use std::fs::File;
use std::io::Cursor;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{gen_keypair,precompute};

pub fn main() {

	// Alice's key 
	let (mut alice_pk, _) = gen_keypair();

	// Bob's key
	let (_, mut bob_sk) = gen_keypair();

	// Precomputed key
	let pre_key = precompute(&mut alice_pk, &mut bob_sk);

	// Open file 
	let mut source = File::open("test.mp3").unwrap();

	// File mimetype and size 
	let file_size = source.metadata().unwrap().len() as u32;
	let mime = "audio/mp3".to_owned();

	// Destinations
	let mut dest1 = Cursor::new(Vec::new());
	let mut dest2 = Cursor::new(Vec::new());

	let mut decrypted_bytes = vec![0u8; file_size as usize];

	{
		// Encrypt 
		let mut pipe1 = SPipe::new(&pre_key, &mut source, &mut dest1);
		pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime).unwrap();
		pipe1.dest.set_position(0);

		// Decrypt
		let mut pipe2 = SPipe::new(&pre_key, &mut pipe1, &mut dest2);
		pipe2.decrypt().unwrap();
		pipe2.dest.set_position(0);

		// Read decrypted bytes
		pipe2.read_exact(&mut decrypted_bytes).unwrap();
	}

	// Read plain bytes
	let mut file = File::open("./test.mp3").unwrap();
	let mut plain_bytes = vec![0u8; file_size as usize];
	file.read_exact(&mut plain_bytes).unwrap();

	// Compare decrypted bytes to plain bytes
	assert_eq!(plain_bytes, decrypted_bytes);	
}
```

