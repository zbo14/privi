// #![feature(test)]

extern crate byteorder;
extern crate sodiumoxide;
// extern crate test;

use std::io::{Cursor,Error,Read,Write};
// use std::sync::{Arc,Mutex};
// use std::sync::mpsc::{Receiver,Sender,channel};
// use std::thread;

use self::byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
// use self::sodiumoxide::crypto::box_;
use self::sodiumoxide::crypto::secretbox;

pub const DEFAULT_CHUNK_SIZE : u32 = 16384;

#[derive(Debug,PartialEq)]
pub struct Header {
	encrypted_body_size: u32, 
	frame_size: u32,
	mime: String,
	num_frames: u32,
}

impl Header {

	fn decode<R: Read>(r: &mut R) -> Result<Header,Error> {
		let encrypted_body_size = r.read_u32::<BigEndian>()?;
		let frame_size = r.read_u32::<BigEndian>()?;
		let mime_size = r.read_u32::<BigEndian>()?;
		let mut mime = vec![0u8; mime_size as usize];
		r.read_exact(&mut mime)?;
		let mime = String::from_utf8(mime).unwrap();let num_frames = r.read_u32::<BigEndian>()?;
		Ok(Header {
			encrypted_body_size,
			frame_size,
			mime,
			num_frames,
		})
	}

	fn decrypt<R: Read>(key: &secretbox::Key, nonce: &secretbox::Nonce, r: &mut R) -> Result<Header,Error> {
		let size = r.read_u32::<BigEndian>()?;
		let mut encrypted = vec![0u8; size as usize];
		r.read_exact(&mut encrypted)?;
		let decrypted = secretbox::xsalsa20poly1305::open(&encrypted, &nonce, key).unwrap();
		Header::decode(&mut Cursor::new(decrypted))
	}

	fn encode<W: Write>(&self, w: &mut W) -> Result<(),Error> {
		w.write_u32::<BigEndian>(self.encrypted_body_size)?;
		w.write_u32::<BigEndian>(self.frame_size)?;
		let mime = self.mime.as_bytes();
		w.write_u32::<BigEndian>(mime.len() as u32)?;
		w.write_all(mime)?;
		w.write_u32::<BigEndian>(self.num_frames)
	}

	fn encrypt<W: Write>(&self, key: &secretbox::Key, nonce: &secretbox::Nonce, w: &mut W) -> Result<(),Error> {
		let mut encoded = Vec::with_capacity(self.encoded_header_size());
		self.encode(&mut encoded)?;
		let encrypted = secretbox::xsalsa20poly1305::seal(&encoded, nonce, key);
		w.write_u32::<BigEndian>(encrypted.len() as u32)?;
		w.write_all(&encrypted)
	}

	fn encoded_header_size(&self) -> usize {
		4 * 4 + self.mime.as_bytes().len()
	}

	pub fn encrypted_header_size(&self) -> usize {
		4 + self.encoded_header_size() + secretbox::xsalsa20poly1305::MACBYTES
	}
}

pub fn encrypted_body_size(chunk_size: u32, file_size: u32) -> (u32,u32,u32) {
	let overhead = secretbox::xsalsa20poly1305::MACBYTES as u32;
	let encrypted_body_size;
	let frame_size = chunk_size + overhead;
	let mut num_frames = file_size / chunk_size;
	let rem = file_size % chunk_size;
	if rem == 0 {
		encrypted_body_size = num_frames * frame_size;
	} else {
		encrypted_body_size = num_frames * frame_size + rem + overhead;
		num_frames += 1;
	}
	(encrypted_body_size, frame_size, num_frames)
}

pub fn header(chunk_size: u32, file_size: u32, mime: String) -> Header {
	let (encrypted_body_size, frame_size, num_frames) = encrypted_body_size(chunk_size, file_size);
	Header{
		encrypted_body_size,
		frame_size,		
		mime,
		num_frames,
	}
}

#[derive(Debug)]
pub struct Pipe<'a, T: Read + Write + 'a, U: Read + Write + 'a> {
	dest: &'a mut U,
	key: &'a secretbox::Key,
	nonce: &'a secretbox::Nonce,
	source: &'a mut T,
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> Read for Pipe<'a,T,U> {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
		self.dest.read(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> Write for Pipe<'a,T,U> {
	
	fn flush(&mut self) -> Result<(),Error> {
		self.source.flush()
	}

	fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
		self.source.write(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> Pipe<'a,T,U> {
	
	pub fn new(key: &'a secretbox::Key, nonce: &'a secretbox::Nonce, source: &'a mut T, dest: &'a mut U) -> Pipe<'a,T,U> {
		Pipe{
			dest,
			key,
			nonce,
			source,
		}
	}

	pub fn decrypt(&mut self) -> Result<(),String> {
		let header = Header::decrypt(self.key, self.nonce, self.source).map_err(|err| err.to_string())?;
		let mut frame = vec![0u8; header.frame_size as usize];
		let mut size_left = header.encrypted_body_size;
		while size_left > header.frame_size {
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let chunk = &secretbox::open(&frame, self.nonce, self.key).unwrap();
			self.dest.write_all(&chunk).map_err(|err| err.to_string())?;
			size_left -= header.frame_size;
		}
		if size_left > 0 {
			frame.truncate(size_left as usize);
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let chunk = secretbox::open(&frame, self.nonce, self.key).unwrap();
			self.dest.write_all(&chunk).map_err(|err| err.to_string())?;
		}
		Ok(())
	}

	pub fn encrypt(&mut self, chunk_size: u32, file_size: u32, mime: String) -> Result<(),String> {
		let mut chunk = vec![0u8; chunk_size as usize];
		let header = header(chunk_size, file_size, mime);
		let mut size_left = file_size;
		header.encrypt(&self.key, &self.nonce, &mut self.dest).map_err(|err| err.to_string())?;
		while size_left > chunk_size {
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let frame = secretbox::seal(&chunk, self.nonce, self.key);
			self.dest.write_all(&frame).map_err(|err| err.to_string())?;
			size_left -= chunk_size;
		} 
		if size_left > 0 {
			chunk.truncate(size_left as usize);
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let frame = secretbox::seal(&chunk, self.nonce, self.key);
			self.dest.write_all(&frame).map_err(|err| err.to_string())?;
		}
		Ok(())
	}
}

mod example {

	use super::*;

	use std::fs::File;
	use std::io::Cursor;

	pub fn main() {

		// Generate key
		let key = secretbox::xsalsa20poly1305::gen_key();

		// Generate nonce 
		let nonce = secretbox::xsalsa20poly1305::gen_nonce();

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
			let mut pipe1 = Pipe::new(&key, &nonce, &mut source, &mut dest1);
			pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime).unwrap();
			pipe1.dest.set_position(0);

			// Decrypt
			let mut pipe2 = Pipe::new(&key, &nonce, &mut pipe1, &mut dest2);
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
}

#[cfg(test)]
mod tests {

	use super::*;
	use std::fs::File;
	// use self::test::Bencher;

	const ALTERNATE_CHUNK_SIZE : u32 = 32768;

	// fn precompute_key() -> box_::curve25519xsalsa20poly1305::PrecomputedKey {
	//	let (mut pub_key, _) = box_::curve25519xsalsa20poly1305::gen_keypair();
	//	let (_, mut sec_key) = box_::curve25519xsalsa20poly1305::gen_keypair();
	//	box_::curve25519xsalsa20poly1305::precompute(&mut pub_key, &mut sec_key)
	// }

	fn gen_key_nonce() -> (secretbox::Key, secretbox::Nonce) {
		let key = secretbox::gen_key();
		let nonce = secretbox::gen_nonce();
		(key, nonce)
	}

	fn new_header() -> Header {
		let encrypted_body_size = 49225 + secretbox::xsalsa20poly1305::MACBYTES as u32;
		let frame_size = DEFAULT_CHUNK_SIZE + secretbox::xsalsa20poly1305::MACBYTES as u32;
		Header{
			encrypted_body_size,
			frame_size,
			mime: "image/png".to_owned(),
			num_frames: 4,
		}
	}

	fn total_encrypted_size(chunk_size: u32, file_size: u32, mime: String) -> u32 {
		let header = header(chunk_size, file_size, mime);
		header.encrypted_header_size() as u32 + header.encrypted_body_size
	}

	#[test]
	fn test_header() {

		let header = new_header();

		let mut rw = Cursor::new(Vec::new());
		header.encode(&mut rw).unwrap();
		rw.set_position(0);
		assert_eq!(header, Header::decode(&mut rw).unwrap());

		let mut rw = Cursor::new(Vec::new());
		let (key, nonce) = gen_key_nonce();
		header.encrypt(&key, &nonce, &mut rw).unwrap();
		rw.set_position(0);
		assert_eq!(header, Header::decrypt(&key, &nonce, &mut rw).unwrap())
	}

	fn test_pipe(chunk_size: u32) {

		let (key, nonce) = gen_key_nonce();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut dest1 = Cursor::new(Vec::new());
		let mut dest2 = Cursor::new(Vec::new());

		{
			let mut pipe1 = Pipe::new(&key, &nonce, &mut source, &mut dest1);
			pipe1.encrypt(chunk_size, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.set_position(0);

			let mut pipe2 = Pipe::new(&key, &nonce, &mut pipe1, &mut dest2);
			pipe2.decrypt().unwrap();
			pipe2.dest.set_position(0);
		}	

		let decrypted_bytes = dest2.into_inner();
		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
	}

	fn test_pipes(chunk_size_1: u32, chunk_size_2: u32) {

		let (key1, nonce1) = gen_key_nonce();
		let (key2, nonce2) = gen_key_nonce();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut dest1 = Cursor::new(Vec::new());
		let mut dest2 = Cursor::new(Vec::new());
		let mut dest3 = Cursor::new(Vec::new());
		let mut dest4 = Cursor::new(Vec::new());

		{
			let mut pipe1 = Pipe::new(&key1, &nonce1, &mut source, &mut dest1);
			pipe1.encrypt(chunk_size_1, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.set_position(0); 

			let mut pipe2 = Pipe::new(&key2, &nonce2, &mut pipe1, &mut dest2);
			let size = total_encrypted_size(chunk_size_1, file_size, "audio/mp3".to_owned());
			pipe2.encrypt(chunk_size_2, size, String::new()).unwrap();
			pipe2.dest.set_position(0);

			let mut pipe3 = Pipe::new(&key2, &nonce2, &mut pipe2, &mut dest3);
			pipe3.decrypt().unwrap();
			pipe3.dest.set_position(0);

			println!("here");

			let mut pipe4 = Pipe::new(&key1, &nonce1, &mut pipe3, &mut dest4);
			pipe4.decrypt().unwrap();
			pipe4.dest.set_position(0);
		}	

		let decrypted_bytes = dest4.into_inner();
		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
	}

	#[test]
	fn test_pipe_with_default_chunk_size() {
		test_pipe(DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_pipe_with_alternate_chunk_size() {
		test_pipe(ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_pipes_with_default_chunk_size() {
		test_pipes(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_pipes_with_different_chunk_sizes() {
		test_pipes(DEFAULT_CHUNK_SIZE, ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_pipe_example() {
		example::main()
	}

	// #[bench]
	// fn bench_pipe(b: &mut Bencher) {
	// 	b.iter(|| test_pipe(DEFAULT_CHUNK_SIZE));
	// }
}