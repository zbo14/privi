// #![feature(test)]

extern crate bufstream;
extern crate byteorder;
extern crate sodiumoxide;
// extern crate test;

use std::io::{Cursor,Error,Read,Write};
use std::net::TcpStream;

use self::bufstream::BufStream;
use self::byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use self::sodiumoxide::crypto::box_;
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
        let decrypted = secretbox::open(&encrypted, nonce, key).unwrap();
        let header = Header::decode(&mut Cursor::new(decrypted))?;
        Ok(header)
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
        let encrypted = secretbox::seal(&encoded, nonce, key);
        w.write_u32::<BigEndian>(encrypted.len() as u32)?;
        w.write_all(&encrypted)
    }

    fn encoded_header_size(&self) -> usize {
        4 * 4 + self.mime.as_bytes().len()
    }

    pub fn encrypted_header_size(&self) -> usize {
        4 + self.encoded_header_size() + secretbox::MACBYTES
    }
}

pub fn encrypted_body_size(chunk_size: u32, file_size: u32) -> (u32,u32,u32) {
    let overhead = secretbox::MACBYTES as u32;
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
pub struct Pipe<'a, C: Read + Write + 'a> {
    cipher: &'a mut C,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

impl<'a, C: Read + Write + 'a> Read for Pipe<'a,C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.cipher.read(buf)
    }
}

impl<'a, C: Read + Write + 'a> Write for Pipe<'a,C> {

    fn flush(&mut self) -> Result<(),Error> {
        self.cipher.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
        self.cipher.write(buf)
    }
}

impl<'a, C: Read + Write + 'a> Pipe<'a,C> {
    
    pub fn new(cipher: &'a mut C, key: secretbox::Key, nonce: secretbox::Nonce) -> Pipe<'a,C> {
        Pipe{
            cipher,
            key,
            nonce,
        }
    }

    pub fn empty(cipher: &'a mut C) -> Pipe<'a,C> {
        let key = secretbox::Key::from_slice(&[0u8; secretbox::KEYBYTES]).unwrap();
        let nonce = secretbox::Nonce::from_slice(&[0u8; secretbox::NONCEBYTES]).unwrap();
        Pipe::new(cipher, key, nonce)
    }

    pub fn decrypt<P: Write>(&mut self, plain: &mut P) -> Result<Header,String> {
        let header = Header::decrypt(&self.key, &self.nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        let mut frame = vec![0u8; header.frame_size as usize];
        let mut size_left = header.encrypted_body_size;
        while size_left > header.frame_size {
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = &secretbox::open(&frame, &self.nonce, &self.key).unwrap();
            plain.write_all(&chunk).map_err(|err| err.to_string())?;
            size_left -= header.frame_size;
        }
        if size_left > 0 {
            if size_left < header.frame_size {
                frame.truncate(size_left as usize);
            }
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = secretbox::open(&frame, &self.nonce, &self.key).unwrap();
            plain.write_all(&chunk).map_err(|err| err.to_string())?;
        }
        Ok(header)
    }

    pub fn encrypt<P: Read>(&mut self, chunk_size: u32, file_size: u32, mime: String, plain: &mut P) -> Result<Header,String> {
        let mut chunk = vec![0u8; chunk_size as usize];
        let header = header(chunk_size, file_size, mime);
        let mut size_left = file_size;
        header.encrypt(&self.key, &self.nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        while size_left > chunk_size {
            plain.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
            size_left -= chunk_size;
        } 
        if size_left > 0 {
            if size_left < chunk_size {
                chunk.truncate(size_left as usize);
            }
            plain.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
        }
        Ok(header)
    }
}

#[derive(Debug)]
pub struct Conn<'a> {
    nonce: box_::Nonce,
    pipe: Pipe<'a,BufStream<TcpStream>>,
    pre_key: box_::PrecomputedKey,
}

const HANDSHAKE_SIZE : usize = secretbox::KEYBYTES + secretbox::NONCEBYTES + box_::MACBYTES;

impl<'a> Read for Conn<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.pipe.read(buf)
    }
}

impl<'a> Write for Conn<'a> {

    fn flush(&mut self) -> Result<(),Error> {
        self.pipe.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
        self.pipe.write(buf)
    }
}

impl<'a> Conn<'a> {

    fn new(nonce: box_::Nonce, pipe: Pipe<'a,BufStream<TcpStream>>, pub_key: &box_::PublicKey, sec_key: &box_::SecretKey) -> Conn<'a> {
        let pre_key = box_::precompute(pub_key, sec_key);
        Conn{
            nonce,
            pipe,
            pre_key,
        }
    }

    fn cipher(stream: &TcpStream) -> BufStream<TcpStream> {
        let stream = stream.try_clone().unwrap();
        BufStream::new(stream)
    }

    fn write_handshake(&mut self) -> Result<(),String> {
        let mut handshake = self.pipe.key.0.to_vec();
        handshake.extend_from_slice(&self.pipe.nonce.0);
        let handshake = box_::seal_precomputed(&handshake, &self.nonce, &self.pre_key);
        self.write_all(&handshake).map_err(|err| err.to_string())?;
        self.flush().map_err(|err| err.to_string())
    }

    fn read_handshake(&mut self) -> Result<(),String> {
        let mut handshake = vec![0u8; HANDSHAKE_SIZE];
        self.read_exact(&mut handshake).map_err(|err| err.to_string())?;
        let handshake = box_::open_precomputed(&handshake, &self.nonce, &self.pre_key).unwrap();
        self.pipe.key = secretbox::Key::from_slice(&handshake[..secretbox::KEYBYTES]).unwrap();
        self.pipe.nonce = secretbox::Nonce::from_slice(&handshake[secretbox::KEYBYTES..]).unwrap();
        Ok(())
    }
}

mod example {

    use super::*;

    use std::fs::File;
    use std::io::Cursor;

    pub fn pipe() {

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
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::File;
    use std::net::{TcpListener,TcpStream};
    use std::thread;
    // use self::test::Bencher;

    const ALTERNATE_CHUNK_SIZE : u32 = 32768;

    fn gen_key_nonce() -> (secretbox::Key, secretbox::Nonce) {
        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        (key, nonce)
    }

    fn new_header() -> Header {
        let encrypted_body_size = 49225 + secretbox::MACBYTES as u32;
        let frame_size = DEFAULT_CHUNK_SIZE + secretbox::MACBYTES as u32;
        Header{
            encrypted_body_size,
            frame_size,
            mime: "image/png".to_owned(),
            num_frames: 4,
        }
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

    fn total_encrypted_size(chunk_size: u32, file_size: u32, mime: String) -> u32 {
        let header = header(chunk_size, file_size, mime);
        header.encrypted_header_size() as u32 + header.encrypted_body_size
    }

    fn test_pipe(chunk_size: u32) {

        let (key, nonce) = gen_key_nonce();

        let mut plain1 = File::open("test.mp3").unwrap();
        let mut plain2 = Cursor::new(Vec::new());

        let meta = plain1.metadata().unwrap();
        let file_size = meta.len() as u32;

        let mut cipher = Cursor::new(Vec::new());

        let header = header(chunk_size, file_size, "audio/mp3".to_owned());

        {
            let mut pipe1 = Pipe::new(&mut cipher, key.clone(), nonce.clone());
            let hdr = pipe1.encrypt(chunk_size, file_size, "audio/mp3".to_owned(), &mut plain1).unwrap();
            assert_eq!(header, hdr);
            pipe1.cipher.set_position(0);
        }

        {
            let mut pipe2 = Pipe::new(&mut cipher, key, nonce);
            let hdr = pipe2.decrypt(&mut plain2).unwrap();
            assert_eq!(header, hdr);
        }   

        let mut file = File::open("test.mp3").unwrap();
        let mut plain_bytes = vec![0u8; file_size as usize];
        file.read_exact(&mut plain_bytes).unwrap();
        let decrypted_bytes = plain2.into_inner();

        assert_eq!(plain_bytes, decrypted_bytes);
    }

    #[test]
    fn test_conn() {

        let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
        let handle = thread::spawn(|| {
            TcpStream::connect("127.0.0.1:12345").unwrap()
        });

        let (server_stream, _) = listener.accept().unwrap();
        let client_stream = handle.join().unwrap();

        let (key, nonce) = gen_key_nonce();
        let nonce_ = box_::gen_nonce();
        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, server_sk) = box_::gen_keypair();

        let mut client_cipher = Conn::cipher(&client_stream);
        let client_pipe = Pipe::new(&mut client_cipher, key.clone(), nonce.clone());
        let mut client_conn = Conn::new(nonce_, client_pipe, &server_pk, &client_sk);

        let mut server_cipher = Conn::cipher(&server_stream);
        let server_pipe = Pipe::empty(&mut server_cipher);
        let mut server_conn = Conn::new(nonce_, server_pipe, &client_pk, &server_sk);

        client_conn.write_handshake().unwrap();
        server_conn.read_handshake().unwrap();

        assert_eq!(key, server_conn.pipe.key);
        assert_eq!(nonce, server_conn.pipe.nonce);
    }

    fn test_pipes(chunk_size1: u32, chunk_size2: u32) {

        let (key1, nonce1) = gen_key_nonce();
        let (key2, nonce2) = gen_key_nonce();

        let mut plain1 = File::open("test.mp3").unwrap();
        let mut plain2 = Cursor::new(Vec::new());

        let meta = plain1.metadata().unwrap();
        let file_size1 = meta.len() as u32;
        let file_size2 = total_encrypted_size(chunk_size1, file_size1, "audio/mp3".to_owned());

        let mut cipher1 = Cursor::new(Vec::new());
        let mut cipher2 = Cursor::new(Vec::new());

        let header1 = header(chunk_size1, file_size1, "audio/mp3".to_owned());
        let header2 = header(chunk_size2, file_size2, String::new());

        {
            let mut pipe1 = Pipe::new(&mut cipher1, key1.clone(), nonce1.clone());
            let hdr = pipe1.encrypt(chunk_size1, file_size1, "audio/mp3".to_owned(), &mut plain1).unwrap();
            assert_eq!(header1, hdr);
            pipe1.cipher.set_position(0); 
        }

        {
            let mut pipe2 = Pipe::new(&mut cipher2, key2.clone(), nonce2.clone());
            let hdr = pipe2.encrypt(chunk_size2, file_size2, String::new(), &mut cipher1).unwrap();
            assert_eq!(header2, hdr);
            pipe2.cipher.set_position(0); 
        }

        cipher1.set_position(0);

        {
            let mut pipe3 = Pipe::new(&mut cipher2, key2, nonce2);
            let hdr = pipe3.decrypt(&mut cipher1).unwrap();
            assert_eq!(header2, hdr);
            pipe3.cipher.set_position(0); 
        }

        cipher1.set_position(0);

        {
            let mut pipe4 = Pipe::new(&mut cipher1, key1, nonce1);
            let hdr = pipe4.decrypt(&mut plain2).unwrap();
            assert_eq!(header1, hdr);
        }   

        let mut file = File::open("test.mp3").unwrap();
        let mut plain_bytes = vec![0u8; file_size1 as usize];
        file.read_exact(&mut plain_bytes).unwrap();
        let decrypted_bytes = plain2.into_inner();

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
        example::pipe()
    }

    // #[bench]
    // fn bench_pipe(b: &mut Bencher) {
    //  b.iter(|| test_pipe(DEFAULT_CHUNK_SIZE));
    // }
}