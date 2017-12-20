// #![feature(test)]

extern crate byteorder;
extern crate sodiumoxide;
extern crate test;

use std::io::{Cursor,Error,Read,Write};
use std::sync::{Arc,Mutex};
use std::sync::atomic::{ATOMIC_BOOL_INIT,AtomicBool,Ordering};
use std::sync::mpsc::{Receiver,Sender,channel};
use std::thread;

use self::byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use self::sodiumoxide::crypto::box_;
use self::sodiumoxide::crypto::secretbox;

const DECRYPT : u8 = 0x01;
const ENCRYPT : u8 = 0x02;

pub const DEFAULT_CHUNK_SIZE : u32 = 16384;
pub const DEFAULT_POOL_SIZE : usize = 4; // what should this be?

#[derive(Debug,PartialEq)]
pub struct Header {
	encrypted_body_size: u32, 
	frame_size: u32,
	key: secretbox::Key,
	mime: String,
	nonce: secretbox::Nonce,
	num_frames: u32,
}

impl Header {

	fn decode<R: Read>(r: &mut R) -> Result<Header,Error> {
		let encrypted_body_size = r.read_u32::<BigEndian>()?;
		let frame_size = r.read_u32::<BigEndian>()?;
		let mut key = [0u8; secretbox::xsalsa20poly1305::KEYBYTES];
		r.read_exact(&mut key)?;	
		let key = secretbox::xsalsa20poly1305::Key::from_slice(&key).unwrap();
		let mime_size = r.read_u32::<BigEndian>()?;
		let mut mime = vec![0u8; mime_size as usize];
		r.read_exact(&mut mime)?;
		let mime = String::from_utf8(mime).unwrap();
		let mut nonce = [0u8; secretbox::xsalsa20poly1305::NONCEBYTES];
		r.read_exact(&mut nonce)?;
		let nonce = secretbox::xsalsa20poly1305::Nonce::from_slice(&nonce).unwrap();
		let num_frames = r.read_u32::<BigEndian>()?;
		Ok(Header {
			encrypted_body_size,
			frame_size,
			key,
			mime,
			nonce,
			num_frames,
		})
	}

	fn decrypt<R: Read>(pre_key: &box_::PrecomputedKey, r: &mut R) -> Result<Header,Error> {
		let mut nonce = [0u8; box_::curve25519xsalsa20poly1305::NONCEBYTES];
		r.read_exact(&mut nonce)?;
		let nonce = box_::curve25519xsalsa20poly1305::Nonce::from_slice(&nonce).unwrap();
		let size = r.read_u32::<BigEndian>()?;
		let mut encrypted = vec![0u8; size as usize];
		r.read_exact(&mut encrypted)?;
		let decrypted = box_::curve25519xsalsa20poly1305::open_precomputed(&encrypted, &nonce, pre_key).unwrap();
		Header::decode(&mut Cursor::new(decrypted))
	}

	fn encode<W: Write>(&self, w: &mut W) -> Result<(),Error> {
		w.write_u32::<BigEndian>(self.encrypted_body_size)?;
		w.write_u32::<BigEndian>(self.frame_size)?;
		w.write_all(&self.key.0)?;
		let mime = self.mime.as_bytes();
		w.write_u32::<BigEndian>(mime.len() as u32)?;
		w.write_all(mime)?;
		w.write_all(&self.nonce.0)?;
		w.write_u32::<BigEndian>(self.num_frames)
	}

	fn encrypt<W: Write>(&self, pre_key: &box_::PrecomputedKey, w: &mut W) -> Result<(),Error> {
		let mut encoded = Vec::with_capacity(self.encoded_header_size());
		self.encode(&mut encoded)?;
		let nonce = box_::curve25519xsalsa20poly1305::gen_nonce();
		w.write_all(&nonce.0)?;
		let encrypted = box_::curve25519xsalsa20poly1305::seal_precomputed(&encoded, &nonce, pre_key);
		w.write_u32::<BigEndian>(encrypted.len() as u32)?;
		w.write_all(&encrypted)
	}

	fn encoded_header_size(&self) -> usize {
		4 * 4 + secretbox::xsalsa20poly1305::KEYBYTES + secretbox::xsalsa20poly1305::NONCEBYTES + self.mime.as_bytes().len()
	}

	pub fn encrypted_header_size(&self) -> usize {
		box_::curve25519xsalsa20poly1305::NONCEBYTES + 4 + self.encoded_header_size() + box_::curve25519xsalsa20poly1305::MACBYTES
	}
}

#[derive(Debug)]
pub struct Job {
	bytes: Vec<u8>,
	idx: usize,
	key: secretbox::xsalsa20poly1305::Key,
	nonce: secretbox::xsalsa20poly1305::Nonce,
	op: u8,
	tx: Sender<(Vec<u8>,usize)>,
}

impl Job {
	pub fn new(bytes: &[u8], idx: usize, key: &secretbox::xsalsa20poly1305::Key, nonce: &secretbox::xsalsa20poly1305::Nonce, op: u8, tx: Sender<(Vec<u8>, usize)>) -> Job {
		Job {
			bytes: bytes.to_owned(),
			idx,
			key: key.clone(),
			nonce: nonce.clone(),
			op,
			tx,
		}
	}
}

// 	ThreadPool adapted from https://doc.rust-lang.org/book/second-edition/ch20-04-storing-threads.html 
//
//	---------------- BEGIN LICENSE ----------------
//
// 	MIT License
//
// 	Copyright (c) 2011 The Rust Project Developers
//
// 	Permission is hereby granted, free of charge, to any person obtaining a copy
// 	of this software and associated documentation files (the "Software"), to deal
// 	in the Software without restriction, including without limitation the rights
// 	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// 	copies of the Software, and to permit persons to whom the Software is
// 	furnished to do so, subject to the following conditions:
//
// 	The above copyright notice and this permission notice shall be included in all
// 	copies or substantial portions of the Software.
//
// 	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// 	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// 	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// 	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// 	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// 	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// 	SOFTWARE.

#[derive(Debug)]
pub struct Pool {
	running: Arc<AtomicBool>,
	rx: Arc<Mutex<Receiver<Job>>>,
	size: usize,
	tx: Sender<Job>,
	workers: Vec<Worker>,
}

impl Pool {

	pub fn new(size: usize) -> Pool {
		let running = Arc::new(ATOMIC_BOOL_INIT);
		let (tx, rx) = channel();
		let rx = Arc::new(Mutex::new(rx));
		Pool{
			running,
			rx,
			size,
			tx,
			workers: Vec::new(),
		}
	}

	fn send(job: Job, sender: &Sender<Job>) -> Result<(),String> {
		sender.send(job).map_err(|err| err.to_string())
	}

	fn sender(&self) -> Sender<Job> {
		self.tx.clone()
	}

	pub fn start(&mut self) -> Result<(),String> {
		if self.running.compare_and_swap(false, true, Ordering::Relaxed) {
			return Err("Pool is already running".to_owned())
		}
		self.workers = Vec::with_capacity(self.size);
		for id in 0..self.size {
			self.workers.push(Worker::new(id, self.running.clone(), self.rx.clone()));
		}
		Ok(())
	}

	pub fn stop(&self) -> Result<(),String> {
		if !self.running.compare_and_swap(true, false, Ordering::Relaxed) {
			Err("Pool is not running".to_owned())
		} else {
			Ok(())
		}
	}
}

#[derive(Debug)]
pub struct Worker {
	id: usize,
	thread: thread::JoinHandle<()>,
}

impl Worker {
	fn new(id: usize, running: Arc<AtomicBool>, rx: Arc<Mutex<Receiver<Job>>>) -> Worker {
		let thread = thread::spawn(move || {
			// println!("Starting thread {}...", id);
			while running.load(Ordering::Relaxed) {
				if let Ok(lock) = rx.lock() {
					if let Ok(job) = lock.recv() {
						if job.op == DECRYPT {
							let chunk = secretbox::open(&job.bytes, &job.nonce, &job.key).unwrap();
							job.tx.send((chunk, job.idx)).unwrap();	
						} else if job.op == ENCRYPT {
							let frame = secretbox::seal(&job.bytes, &job.nonce, &job.key);
							job.tx.send((frame, job.idx)).unwrap();	
						}
					}
				}
			}
			// println!("Stopping thread {}...", id);
		});
		Worker{
			id,
			thread,
		}
	}
}

//	----------------- END LICENSE -----------------

#[derive(Debug)]
pub struct TPipe<'a, T: Read + Write + 'a, U: Read + Write> {
	dest: Arc<Mutex<U>>,
	pre_key: &'a box_::PrecomputedKey,
	rx: Arc<Mutex<Receiver<(Vec<u8>,usize)>>>,
	sender: Sender<Job>,
	source: &'a mut T,
	tx: Sender<(Vec<u8>,usize)>,
}

macro_rules! vecvec {
    ($t:ty; $e:expr) => {{
        let mut vec: Vec<Vec<$t>> = Vec::with_capacity($e);
        for _ in 0..$e {
            vec.push(vec![]);
        } 
        vec
    }};
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

pub fn header(chunk_size: u32, file_size: u32, key: &secretbox::Key, mime: String, nonce: &secretbox::Nonce) -> Header {
	let (encrypted_body_size, frame_size, num_frames) = encrypted_body_size(chunk_size, file_size);
	Header{
		encrypted_body_size,
		frame_size,			
		key: key.clone(),
		mime,
		nonce: nonce.clone(),
		num_frames,
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write> Read for TPipe<'a, T, U> {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
		self.dest.lock().unwrap().read(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write> Write for TPipe<'a, T, U> {

	fn flush(&mut self) -> Result<(),Error> {
		self.source.flush()
	}

	fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
		self.source.write(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Send + Read + Write + 'static> TPipe<'a, T, U> {

	pub fn new(pool: &'a Pool, pre_key: &'a box_::curve25519xsalsa20poly1305::PrecomputedKey, source: &'a mut T, dest: U) -> TPipe<'a,T,U> {
		let dest = Arc::new(Mutex::new(dest));
		let sender = pool.sender();
		let (tx, rx) = channel();
		let rx = Arc::new(Mutex::new(rx));
		TPipe{
			dest,
			pre_key,
			rx,
			sender,
			source,
			tx,
		}
	}

	pub fn decrypt(&mut self) -> Result<(),String> {
		let header = Header::decrypt(&self.pre_key, self.source).map_err(|err| err.to_string())?;
		let num_frames = header.num_frames;
		let dest = self.dest.clone();
		let rx = self.rx.clone();
		let handle : thread::JoinHandle<Result<(),String>> = thread::spawn(move || {
			let mut chunks = vecvec![u8; num_frames as usize];
			let mut next = 0;
			let mut dest = dest.lock().unwrap();
			let rx = rx.lock().unwrap();
			while next < num_frames {
				if !chunks[next as usize].is_empty() {
					dest.write_all(&chunks[next as usize]).map_err(|err| err.to_string())?;
					next += 1;
				}
				let (chunk, idx) = rx.recv().unwrap();
				if idx == next as usize {
					dest.write_all(&chunk).map_err(|err| err.to_string())?;
					next += 1;
				} else {
					chunks[idx as usize] = chunk;
				}
			}
			Ok(())
		});
		let mut frame = vec![0u8; header.frame_size as usize];
		let mut idx = 0;
		let mut size_left = header.encrypted_body_size;
		while size_left > header.frame_size {
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let job = Job::new(&frame, idx, &header.key, &header.nonce, DECRYPT, self.tx.clone());
			Pool::send(job, &self.sender)?;
			idx += 1;
			size_left -= header.frame_size;
		}
		if size_left > 0 {
			frame.truncate(size_left as usize);
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let job = Job::new(&frame, idx, &header.key, &header.nonce, DECRYPT, self.tx.clone());
			Pool::send(job, &self.sender)?;
		}
		handle.join().unwrap()
	}

	pub fn encrypt(&mut self, chunk_size: u32, file_size: u32, mime: String) -> Result<(),String> {
		let key = secretbox::gen_key();
		let nonce = secretbox::gen_nonce();
		let header = header(chunk_size, file_size, &key, mime, &nonce);
		let dest = self.dest.clone();
		let pre_key = self.pre_key.clone();
		let rx = self.rx.clone();
		let handle : thread::JoinHandle<Result<(),String>> = thread::spawn(move || {
			let mut frames = vecvec![u8; header.num_frames as usize];
			let mut next = 0;
			let mut dest = dest.lock().unwrap();
			let rx = rx.lock().unwrap();
			header.encrypt(&pre_key, &mut *dest).map_err(|err| err.to_string())?;
			while next < header.num_frames {
				if !frames[next as usize].is_empty() {
					dest.write_all(&frames[next as usize]).map_err(|err| err.to_string())?;
					next += 1;
				}
				let (frame, idx) = rx.recv().unwrap();
				if idx == next as usize {
					dest.write_all(&frame).map_err(|err| err.to_string())?;
					next += 1;
				} else {
					frames[idx as usize] = frame; 
				}
			}
			Ok(())
		});
		let mut chunk = vec![0u8; chunk_size as usize];
		let mut idx = 0;
		let mut size_left = file_size;
		while size_left > chunk_size {
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let job = Job::new(&chunk, idx, &key, &nonce, ENCRYPT, self.tx.clone());
			Pool::send(job, &self.sender)?;
			idx += 1;
			size_left -= chunk_size;
		}
		if size_left > 0 {
			chunk.truncate(size_left as usize);
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let job = Job::new(&chunk, idx, &key, &nonce, ENCRYPT, self.tx.clone());
			Pool::send(job, &self.sender)?;
		}
		handle.join().unwrap()
	}
}

#[derive(Debug)]
pub struct SPipe<'a, T: Read + Write + 'a, U: Read + Write + 'a> {
	dest: &'a mut U,
	pre_key: &'a box_::PrecomputedKey,
	source: &'a mut T,
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> Read for SPipe<'a,T,U> {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
		self.dest.read(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> Write for SPipe<'a,T,U> {
	
	fn flush(&mut self) -> Result<(),Error> {
		self.source.flush()
	}

	fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
		self.source.write(buf)
	}
}

impl<'a, T: Read + Write + 'a, U: Read + Write + 'a> SPipe<'a,T,U> {
	
	pub fn new(pre_key: &'a box_::curve25519xsalsa20poly1305::PrecomputedKey, source: &'a mut T, dest: &'a mut U) -> SPipe<'a,T,U> {
		SPipe{
			dest,
			pre_key,
			source,
		}
	}

	pub fn decrypt(&mut self) -> Result<(),String> {
		let header = Header::decrypt(&self.pre_key, self.source).map_err(|err| err.to_string())?;
		let mut frame = vec![0u8; header.frame_size as usize];
		let mut size_left = header.encrypted_body_size;
		while size_left > header.frame_size {
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let chunk = &secretbox::open(&frame, &header.nonce, &header.key).unwrap();
			self.dest.write_all(&chunk).map_err(|err| err.to_string())?;
			size_left -= header.frame_size;
		}
		if size_left > 0 {
			frame.truncate(size_left as usize);
			self.source.read_exact(&mut frame).map_err(|err| err.to_string())?;
			let chunk = secretbox::open(&frame, &header.nonce, &header.key).unwrap();
			self.dest.write_all(&chunk).map_err(|err| err.to_string())?;
		}
		Ok(())
	}

	pub fn encrypt(&mut self, chunk_size: u32, file_size: u32, mime: String) -> Result<(),String> {
		let mut chunk = vec![0u8; chunk_size as usize];
		let key = secretbox::gen_key();
		let nonce = secretbox::gen_nonce();
		let header = header(chunk_size, file_size, &key, mime, &nonce);
		let mut size_left = file_size;
		header.encrypt(&self.pre_key, &mut self.dest).map_err(|err| err.to_string())?;
		while size_left > chunk_size {
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let frame = secretbox::seal(&chunk, &nonce, &key);
			self.dest.write_all(&frame).map_err(|err| err.to_string())?;
			size_left -= chunk_size;
		} 
		if size_left > 0 {
			chunk.truncate(size_left as usize);
			self.source.read_exact(&mut chunk).map_err(|err| err.to_string())?;
			let frame = secretbox::seal(&chunk, &nonce, &key);
			self.dest.write_all(&frame).map_err(|err| err.to_string())?;
		}
		Ok(())
	}
}

mod example {

	use super::*;

	use std::fs::File;
	use std::io::Cursor;

	use self::sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{gen_keypair,precompute};

	pub fn spipe() {

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

	pub fn tpipe() {

		// Alice's key 
		let (mut alice_pk, _) = gen_keypair();

		// Bob's key
		let (_, mut bob_sk) = gen_keypair();

		// Precomputed key
		let pre_key = precompute(&mut alice_pk, &mut bob_sk);

		// Start thread pool
		let mut pool = Pool::new(DEFAULT_POOL_SIZE);
		pool.start().unwrap();

		// Open file 
		let mut source = File::open("test.mp3").unwrap();

		// File mimetype and size 
		let file_size = source.metadata().unwrap().len() as u32;
		let mime = "audio/mp3".to_owned();

		// Destinations
		let dest1 = Cursor::new(Vec::new());
		let dest2 = Cursor::new(Vec::new());

		let mut decrypted_bytes = vec![0u8; file_size as usize];

		{
			// Encrypt 
			let mut pipe1 = TPipe::new(&pool, &pre_key, &mut source, dest1);
			pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime).unwrap();
			pipe1.dest.lock().unwrap().set_position(0);

			// Decrypt
			let mut pipe2 = TPipe::new(&pool, &pre_key, &mut pipe1, dest2);
			pipe2.decrypt().unwrap();
			pipe2.dest.lock().unwrap().set_position(0);

			// Read decrypted bytes
			pipe2.read_exact(&mut decrypted_bytes).unwrap();
		}

		// Read plain bytes
		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		// Compare decrypted bytes to plain bytes
		assert_eq!(plain_bytes, decrypted_bytes);

		// Stop thread pool
		pool.stop().unwrap();
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use std::fs::File;
	use self::test::Bencher;

	const ALTERNATE_CHUNK_SIZE : u32 = 32768;

	fn precompute_key() -> box_::curve25519xsalsa20poly1305::PrecomputedKey {
		let (mut pub_key, _) = box_::curve25519xsalsa20poly1305::gen_keypair();
		let (_, mut sec_key) = box_::curve25519xsalsa20poly1305::gen_keypair();
		box_::curve25519xsalsa20poly1305::precompute(&mut pub_key, &mut sec_key)
	}

	fn new_header(key: &secretbox::xsalsa20poly1305::Key, nonce: &secretbox::xsalsa20poly1305::Nonce) -> Header {
		let encrypted_body_size = 49225 + secretbox::xsalsa20poly1305::MACBYTES as u32;
		let frame_size = DEFAULT_CHUNK_SIZE + secretbox::xsalsa20poly1305::MACBYTES as u32;
		Header{
			encrypted_body_size,
			frame_size,
			key: key.clone(),
			mime: "image/png".to_owned(),
			nonce: nonce.clone(),
			num_frames: 4,
		}
	}

	fn total_encrypted_size(chunk_size: u32, file_size: u32, mime: String) -> u32 {
		let key = secretbox::xsalsa20poly1305::gen_key();
		let nonce = secretbox::xsalsa20poly1305::gen_nonce();
		let header = header(chunk_size, file_size, &key, mime, &nonce);
		header.encrypted_header_size() as u32 + header.encrypted_body_size
	}

	#[test]
	fn test_header() {
		let key = secretbox::xsalsa20poly1305::gen_key();
		let nonce = secretbox::xsalsa20poly1305::gen_nonce();
		let header = new_header(&key, &nonce);

		let mut rw = Cursor::new(Vec::new());
		header.encode(&mut rw).unwrap();
		rw.set_position(0);
		assert_eq!(header, Header::decode(&mut rw).unwrap());

		let mut rw = Cursor::new(Vec::new());
		let pre_key = precompute_key();
		header.encrypt(&pre_key, &mut rw).unwrap();
		rw.set_position(0);
		assert_eq!(header, Header::decrypt(&pre_key, &mut rw).unwrap())
	}

	fn test_spipe(chunk_size: u32) {

		let pre_key = precompute_key();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut dest1 = Cursor::new(Vec::new());
		let mut dest2 = Cursor::new(Vec::new());

		{
			let mut pipe1 = SPipe::new(&pre_key, &mut source, &mut dest1);
			pipe1.encrypt(chunk_size, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.set_position(0);

			let mut pipe2 = SPipe::new(&pre_key, &mut pipe1, &mut dest2);
			pipe2.decrypt().unwrap();
			pipe2.dest.set_position(0);
		}	

		let decrypted_bytes = dest2.into_inner();
		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
	}

	fn test_spipes(chunk_size_1: u32, chunk_size_2: u32) {

		let pre_key1 = precompute_key();
		let pre_key2 = precompute_key();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut dest1 = Cursor::new(Vec::new());
		let mut dest2 = Cursor::new(Vec::new());
		let mut dest3 = Cursor::new(Vec::new());
		let mut dest4 = Cursor::new(Vec::new());

		{
			let mut pipe1 = SPipe::new(&pre_key1, &mut source, &mut dest1);
			pipe1.encrypt(chunk_size_1, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.set_position(0); 

			let mut pipe2 = SPipe::new(&pre_key2, &mut pipe1, &mut dest2);
			let size = total_encrypted_size(chunk_size_1, file_size, "audio/mp3".to_owned());
			pipe2.encrypt(chunk_size_2, size, String::new()).unwrap();
			pipe2.dest.set_position(0);

			let mut pipe3 = SPipe::new(&pre_key2, &mut pipe2, &mut dest3);
			pipe3.decrypt().unwrap();
			pipe3.dest.set_position(0);

			let mut pipe4 = SPipe::new(&pre_key1, &mut pipe3, &mut dest4);
			pipe4.decrypt().unwrap();
			pipe4.dest.set_position(0);
		}	

		let decrypted_bytes = dest4.into_inner();
		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
	}

	fn test_tpipe(chunk_size: u32) {

		let pre_key = precompute_key();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut pool = Pool::new(DEFAULT_POOL_SIZE);
		pool.start().unwrap();

		let dest1 = Cursor::new(Vec::new());
		let dest2 = Cursor::new(Vec::new());

		let mut decrypted_bytes = vec![0u8; file_size as usize];

		{
			let mut pipe1 = TPipe::new(&pool, &pre_key, &mut source, dest1);
			pipe1.encrypt(chunk_size, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.lock().unwrap().set_position(0);

			let mut pipe2 = TPipe::new(&pool, &pre_key, &mut pipe1, dest2);
			pipe2.decrypt().unwrap();
			pipe2.dest.lock().unwrap().set_position(0);

			pipe2.read_exact(&mut decrypted_bytes).unwrap();
		}

		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
		pool.stop().unwrap();
	}

	fn test_tpipes(chunk_size_1: u32, chunk_size_2: u32) {

		let pre_key1 = precompute_key();
		let pre_key2 = precompute_key();

		let mut source = File::open("./test.mp3").unwrap();
		let meta = source.metadata().unwrap();
		let file_size = meta.len() as u32;

		let mut pool = Pool::new(DEFAULT_POOL_SIZE);
		pool.start().unwrap();

		let dest1 = Cursor::new(Vec::new());
		let dest2 = Cursor::new(Vec::new());
		let dest3 = Cursor::new(Vec::new());
		let dest4 = Cursor::new(Vec::new());

		let mut decrypted_bytes = vec![0u8; file_size as usize];

		{

			let mut pipe1 = TPipe::new(&pool, &pre_key1, &mut source, dest1);
			pipe1.encrypt(chunk_size_1, file_size, "audio/mp3".to_owned()).unwrap();
			pipe1.dest.lock().unwrap().set_position(0);

			let mut pipe2 = TPipe::new(&pool, &pre_key2, &mut pipe1, dest2);
			let size = total_encrypted_size(chunk_size_1, file_size, "audio/mp3".to_owned());
			pipe2.encrypt(chunk_size_2, size, String::new()).unwrap();
			pipe2.dest.lock().unwrap().set_position(0);

			let mut pipe3 = TPipe::new(&pool, &pre_key2, &mut pipe2, dest3);
			pipe3.decrypt().unwrap();
			pipe3.dest.lock().unwrap().set_position(0);

			let mut pipe4 = TPipe::new(&pool, &pre_key1, &mut pipe3, dest4);
			pipe4.decrypt().unwrap();
			pipe4.dest.lock().unwrap().set_position(0);

			pipe4.read_exact(&mut decrypted_bytes).unwrap();
		}	

		let mut file = File::open("./test.mp3").unwrap();
		let mut plain_bytes = vec![0u8; file_size as usize];
		file.read_exact(&mut plain_bytes).unwrap();

		assert_eq!(plain_bytes, decrypted_bytes);
		pool.stop().unwrap();
	}

	#[test]
	fn test_spipe_with_default_chunk_size() {
		test_spipe(DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_spipe_with_alternate_chunk_size() {
		test_spipe(ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_spipes_with_default_chunk_size() {
		test_spipes(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_spipes_with_different_chunk_sizes() {
		test_spipes(DEFAULT_CHUNK_SIZE, ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_tpipe_with_default_chunk_size() {
		test_tpipe(DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_tpipe_with_alternate_chunk_size() {
		test_tpipe(ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_tpipes_with_default_chunk_size() {
		test_tpipes(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE)
	}

	#[test]
	fn test_tpipes_with_different_chunk_sizes() {
		test_tpipes(DEFAULT_CHUNK_SIZE, ALTERNATE_CHUNK_SIZE)
	}

	#[test]
	fn test_spipe_example() {
		example::spipe()
	}

	#[test]
	fn test_tpipe_example() {
		example::tpipe()
	}

	#[bench]
	fn bench_spipe(b: &mut Bencher) {
		b.iter(|| test_spipe(DEFAULT_CHUNK_SIZE));
	}

	#[bench]
	fn bench_tpipe(b: &mut Bencher) {

		let mut pool1 = Pool::new(DEFAULT_POOL_SIZE);
		pool1.start().unwrap();

		let mut pool2 = Pool::new(DEFAULT_POOL_SIZE);
		pool2.start().unwrap();

		b.iter(|| {

			let pre_key = precompute_key();

			let mut source = File::open("./test.mp3").unwrap();
			let meta = source.metadata().unwrap();
			let file_size = meta.len() as u32;

			let dest1 = Cursor::new(Vec::new());
			let dest2 = Cursor::new(Vec::new());

			let mut decrypted_bytes = vec![0u8; file_size as usize];

			{
				let mut pipe1 = TPipe::new(&pool1, &pre_key, &mut source, dest1);
				pipe1.encrypt(DEFAULT_CHUNK_SIZE, file_size, "audio/mp3".to_owned()).unwrap();
				pipe1.dest.lock().unwrap().set_position(0);

				let mut pipe2 = TPipe::new(&pool2, &pre_key, &mut pipe1, dest2);
				pipe2.decrypt().unwrap();
				pipe2.dest.lock().unwrap().set_position(0);

				pipe2.read_exact(&mut decrypted_bytes).unwrap();
			}	

			let mut file = File::open("./test.mp3").unwrap();
			let mut plain_bytes = vec![0u8; file_size as usize];
			file.read_exact(&mut plain_bytes).unwrap();

			assert_eq!(plain_bytes, decrypted_bytes);
		});

		pool1.stop().unwrap();
		pool2.stop().unwrap();
	}
}