// #![feature(test)]

extern crate bufstream;
extern crate byteorder;
extern crate sodiumoxide;
// extern crate test;

use std::clone::Clone;
use std::io::{Cursor,Error,Read,Write};
use std::net::{TcpListener,TcpStream};

use self::bufstream::BufStream;
use self::byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use self::sodiumoxide::crypto::{box_,sealedbox,secretbox};

pub const DEFAULT_CHUNK_SIZE : u32 = 16384;

#[derive(Debug)]
pub struct BufTcpStream (BufStream<TcpStream>);

impl BufTcpStream {

    pub fn new(stream: TcpStream) -> BufTcpStream {
        BufTcpStream(BufStream::new(stream))
    }
}

impl Clone for BufTcpStream {

    fn clone(&self) -> Self {
        let stream = self.0.get_ref().try_clone().unwrap();
        BufTcpStream(BufStream::new(stream))
    }
}

impl Read for BufTcpStream {

    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.0.read(buf)
    }
}

impl Write for BufTcpStream {

    fn flush(&mut self) -> Result<(),Error> {
        self.0.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
        self.0.write(buf)
    }
}

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
        let mime = String::from_utf8(mime).unwrap();
        let num_frames = r.read_u32::<BigEndian>()?;
        let header = Header{
            encrypted_body_size,
            frame_size,
            mime,
            num_frames,
        };
        Ok(header)
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
pub struct Pipe<C: Read + Write> {
    cipher: C,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

impl<C: Read + Write> PartialEq for Pipe<C> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.nonce == other.nonce
    }
}

impl<C: Read + Write> Read for Pipe<C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.cipher.read(buf)
    }
}

impl<C: Read + Write> Write for Pipe<C> {

    fn flush(&mut self) -> Result<(),Error> {
        self.cipher.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
        self.cipher.write(buf)
    }
}

impl<C: Clone + Read + Write> Pipe<C> {
    
    pub fn new(cipher: C) -> Pipe<C> {
        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        Pipe{
            cipher,
            key,
            nonce,
        }
    }

    pub fn decrypt<W: Write>(&mut self, w: &mut W) -> Result<Header,String> {
        let header = Header::decrypt(&self.key, &self.nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        let mut frame = vec![0u8; header.frame_size as usize];
        let mut size_left = header.encrypted_body_size;
        while size_left > header.frame_size {
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = &secretbox::open(&frame, &self.nonce, &self.key).unwrap();
            w.write_all(&chunk).map_err(|err| err.to_string())?;
            size_left -= header.frame_size;
        }
        if size_left > 0 {
            if size_left < header.frame_size {
                frame.truncate(size_left as usize);
            }
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = secretbox::open(&frame, &self.nonce, &self.key).unwrap();
            w.write_all(&chunk).map_err(|err| err.to_string())?;
        }
        Ok(header)
    }

    pub fn decrypt_self(&mut self) -> Result<Header,String> {
        let mut w = self.cipher.clone();
        let header = self.decrypt(&mut w)?;
        self.cipher = w;
        Ok(header)
    }

    pub fn encrypt<R: Read>(&mut self, chunk_size: u32, file_size: u32, mime: String, r: &mut R) -> Result<Header,String> {
        let mut chunk = vec![0u8; chunk_size as usize];
        let header = header(chunk_size, file_size, mime);
        let mut size_left = file_size;
        header.encrypt(&self.key, &self.nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        while size_left > chunk_size {
            r.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
            size_left -= chunk_size;
        } 
        if size_left > 0 {
            if size_left < chunk_size {
                chunk.truncate(size_left as usize);
            }
            r.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
        }
        Ok(header)
    }

    pub fn encrypt_self(&mut self,  chunk_size: u32, file_size: u32, mime: String) -> Result<Header,String> {
        let mut r = self.cipher.clone();
        self.encrypt(chunk_size, file_size, mime, &mut r)
    }
}

#[derive(Debug,PartialEq)]
pub struct Conn {
    nonce: box_::Nonce,
    pipe: Pipe<BufTcpStream>,
    pre_key: box_::PrecomputedKey,
}

const CONN_HANDSHAKE_SIZE : usize = secretbox::KEYBYTES + secretbox::NONCEBYTES + box_::MACBYTES;

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.pipe.read(buf)
    }
}

impl Write for Conn {

    fn flush(&mut self) -> Result<(),Error> {
        self.pipe.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize,Error> {
        self.pipe.write(buf)
    }
}

impl Conn {

    fn new(nonce: box_::Nonce, pipe: Pipe<BufTcpStream>, pub_key: &box_::PublicKey, sec_key: &box_::SecretKey) -> Conn {
        let pre_key = box_::precompute(pub_key, sec_key);
        Conn{
            nonce,
            pipe,
            pre_key,
        }
    }

    fn write_handshake(&mut self) -> Result<(),String> {
        let mut handshake = self.pipe.key.0.to_vec();
        handshake.extend_from_slice(&self.pipe.nonce.0);
        let handshake = box_::seal_precomputed(&handshake, &self.nonce, &self.pre_key);
        self.write_all(&handshake).map_err(|err| err.to_string())?;
        self.flush().map_err(|err| err.to_string())
    }

    fn read_handshake(&mut self) -> Result<(),String> {
        let mut handshake = vec![0u8; CONN_HANDSHAKE_SIZE];
        self.read_exact(&mut handshake).map_err(|err| err.to_string())?;
        let handshake = box_::open_precomputed(&handshake, &self.nonce, &self.pre_key).unwrap();
        self.pipe.key = secretbox::Key::from_slice(&handshake[..secretbox::KEYBYTES]).unwrap();
        self.pipe.nonce = secretbox::Nonce::from_slice(&handshake[secretbox::KEYBYTES..]).unwrap();
        Ok(())
    }
}

#[derive(Debug)]
pub struct Hub {
    conns: Vec<Conn>,
    listener: TcpListener,
    nonce: box_::Nonce,
    pub_key: box_::PublicKey,
    sec_key: box_::SecretKey,
}

const HUB_HANDSHAKE_SIZE : usize = box_::PUBLICKEYBYTES * 2 + box_::NONCEBYTES + box_::MACBYTES;

impl Hub {

    fn new(addr: &str, pub_key: box_::PublicKey, sec_key: box_::SecretKey) -> Hub {
        let conns = Vec::new();
        let listener = TcpListener::bind(addr).unwrap();
        let nonce = box_::gen_nonce();
        Hub{
            conns,
            listener,
            nonce,
            pub_key,
            sec_key,
        }
    }

    fn accept(&mut self) -> Result<(),String> {
        let (stream, _) = self.listener.accept().map_err(|err| err.to_string())?;
        let mut stream = BufTcpStream::new(stream);
        let (pk, sec_key) = box_::gen_keypair();
        stream.write_all(&pk.0).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())?;
        let mut buf = vec![0u8; HUB_HANDSHAKE_SIZE];
        stream.read_exact(&mut buf).map_err(|err| err.to_string())?;
        let buf = sealedbox::open(&buf, &pk, &sec_key).unwrap();
        let pub_key = box_::PublicKey::from_slice(&buf[..box_::PUBLICKEYBYTES]).unwrap();
        let nonce = box_::Nonce::from_slice(&buf[box_::PUBLICKEYBYTES..]).unwrap();
        let pipe = Pipe::new(stream);
        let mut conn = Conn::new(nonce, pipe, &pub_key, &sec_key);
        conn.write_handshake()?;
        // TODO: conn_routine(s)
        self.conns.push(conn);
        Ok(())
    }

    fn connect(&mut self, addr: &str) -> Result<(),String> {
        let stream = TcpStream::connect(addr).map_err(|err| err.to_string())?;
        let mut stream = BufTcpStream::new(stream);
        let mut pub_key = vec![0u8; box_::PUBLICKEYBYTES];
        stream.read_exact(&mut pub_key).map_err(|err| err.to_string())?;
        let pub_key = box_::PublicKey::from_slice(&pub_key).unwrap();
        let mut handshake = self.pub_key.0.to_vec();
        handshake.extend_from_slice(&self.nonce.0);
        let handshake = sealedbox::seal(&handshake, &pub_key);
        stream.write_all(&handshake).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())?;
        let pipe = Pipe::new(stream);
        let mut conn = Conn::new(self.nonce.clone(), pipe, &pub_key, &self.sec_key);
        conn.read_handshake()?;
        // TODO: conn_routine(s)
        self.conns.push(conn);
        Ok(())
    }
}

mod example {

    use super::*;

    use std::fs::File;
    use std::io::Cursor;

    pub fn pipe() {

        let cipher = Cursor::new(Vec::new());
        let mut plain = File::open("test.mp3").unwrap();
        let mut decrypted = Cursor::new(Vec::new());

        // File mimetype and size 
        let file_size = plain.metadata().unwrap().len() as u32;
        let mime = "audio/mp3".to_owned();

        let mut pipe = Pipe::new(cipher);

        // Encrypt 
        pipe.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime, &mut plain).unwrap();
        pipe.cipher.set_position(0);

        // Decrypt
        pipe.decrypt(&mut decrypted).unwrap();

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

    fn gen_key_nonce() -> (secretbox::Key,secretbox::Nonce) {
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

        let cipher = Cursor::new(Vec::new());
        let mut plain = File::open("test.mp3").unwrap();
        let mut decrypted = Cursor::new(Vec::new());

        let meta = plain.metadata().unwrap();
        let file_size = meta.len() as u32;

        let header = header(chunk_size, file_size, "audio/mp3".to_owned());
        let mut pipe = Pipe::new(cipher);

        let hdr = pipe.encrypt(chunk_size, file_size, "audio/mp3".to_owned(), &mut plain).unwrap();
        assert_eq!(header, hdr);
        pipe.cipher.set_position(0);
        let hdr = pipe.decrypt(&mut decrypted).unwrap();
        assert_eq!(header, hdr);  

        let mut plain = File::open("test.mp3").unwrap();
        let mut plain_bytes = vec![0u8; file_size as usize];
        plain.read_exact(&mut plain_bytes).unwrap();
        let decrypted_bytes = decrypted.into_inner();

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

        let nonce_ = box_::gen_nonce();
        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, server_sk) = box_::gen_keypair();

        let client_cipher = BufTcpStream::new(client_stream);
        let client_pipe = Pipe::new(client_cipher);
        let mut client_conn = Conn::new(nonce_, client_pipe, &server_pk, &client_sk);

        let server_cipher = BufTcpStream::new(server_stream);
        let server_pipe = Pipe::new(server_cipher);
        let mut server_conn = Conn::new(nonce_, server_pipe, &client_pk, &server_sk);

        client_conn.write_handshake().unwrap();
        server_conn.read_handshake().unwrap();

        assert_eq!(client_conn.pipe.key, server_conn.pipe.key);
        assert_eq!(client_conn.pipe.nonce, server_conn.pipe.nonce);
    }

    #[test]
    fn test_hub() {

        let addr1 = "127.0.0.1:54320";
        let addr2 = "127.0.0.1:54321";

        let (pub_key1, sec_key1) = box_::gen_keypair();
        let (pub_key2, sec_key2) = box_::gen_keypair();

        let mut hub1 = Hub::new(addr1, pub_key1, sec_key1);
        let mut hub2 = Hub::new(addr2, pub_key2, sec_key2);

        let handle = thread::spawn(move || {
            hub2.accept().unwrap();
            hub2
        });

        hub1.connect(addr2).unwrap();
        hub2 = handle.join().unwrap();

        assert_eq!(1, hub1.conns.len());
        assert_eq!(1, hub2.conns.len());
        assert_eq!(hub1.conns, hub2.conns);
    }

    fn test_pipes(chunk_size1: u32, chunk_size2: u32) {

        let cipher = Cursor::new(Vec::new());
        let mut plain = File::open("test.mp3").unwrap();
        let mut decrypted = Cursor::new(Vec::new());

        let meta = plain.metadata().unwrap();
        let file_size1 = meta.len() as u32;
        let file_size2 = total_encrypted_size(chunk_size1, file_size1, "audio/mp3".to_owned());

        let header1 = header(chunk_size1, file_size1, "audio/mp3".to_owned());
        let header2 = header(chunk_size2, file_size2, String::new());

        let mut pipe = Pipe::new(cipher);

        let hdr = pipe.encrypt(chunk_size1, file_size1, "audio/mp3".to_owned(), &mut plain).unwrap();
        assert_eq!(header1, hdr);
        pipe.cipher.set_position(0); 
        
        let hdr = pipe.encrypt_self(chunk_size2, file_size2, String::new()).unwrap();
        assert_eq!(header2, hdr);
        pipe.cipher.set_position(0);

        let hdr = pipe.decrypt_self().unwrap();
        assert_eq!(header2, hdr);
        pipe.cipher.set_position(0);

        let hdr = pipe.decrypt(&mut decrypted).unwrap();
        assert_eq!(header1, hdr); 

        let mut plain = File::open("test.mp3").unwrap();
        let mut plain_bytes = vec![0u8; file_size1 as usize];
        plain.read_exact(&mut plain_bytes).unwrap();
        
        let decrypted_bytes = decrypted.into_inner();

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