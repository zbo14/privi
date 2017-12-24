// #![feature(test)]

extern crate bufstream;
extern crate byteorder;
extern crate sodiumoxide;
// extern crate test;

use std::clone::Clone;
use std::collections::HashMap;
use std::io::{Cursor,Error,Read,Write};
use std::net::{TcpListener,TcpStream};
use std::sync::{Arc,Mutex};
use std::sync::mpsc::{Receiver,Sender,channel};
use std::thread;

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

#[derive(Clone,Debug)]
pub struct Pipe<C: Clone + Read + Write> {
    cipher: C,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

impl<C: Clone + Read + Write> PartialEq for Pipe<C> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.nonce == other.nonce
    }
}

impl<C: Clone + Read + Write> Read for Pipe<C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize,Error> {
        self.cipher.read(buf)
    }
}

impl<C: Clone + Read + Write> Write for Pipe<C> {

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
        self.flush().map_err(|err| err.to_string())?;
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
        self.flush().map_err(|err| err.to_string())?;
        Ok(header)
    }

    pub fn encrypt_self(&mut self,  chunk_size: u32, file_size: u32, mime: String) -> Result<Header,String> {
        let mut r = self.cipher.clone();
        self.encrypt(chunk_size, file_size, mime, &mut r)
    }
}

#[derive(Debug)]
pub struct Job{
    chunk_size: u32,
    file_size: u32,
    mime: String,
}

#[derive(Debug)]
pub struct Conn {
    nonce: box_::Nonce,
    pipe: Pipe<BufTcpStream>,
    pre_key: box_::PrecomputedKey,
    recv_buf: Arc<Mutex<Cursor<Vec<u8>>>>,
    send_buf: Arc<Mutex<Cursor<Vec<u8>>>>,
}

impl PartialEq for Conn {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce &&
        self.pipe == other.pipe &&
        self.pre_key == other.pre_key
    }
}

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

    fn encrypt<R: Read>(&mut self, chunk_size: u32, mime: String, r: &mut R, tx: &Sender<Job>) -> Result<(),String> {
        let mut cursor = self.send_buf.lock().unwrap();
        let file_size = r.read_to_end(cursor.get_mut()).map_err(|err| err.to_string())? as u32;
        let job = Job{chunk_size, file_size, mime};
        tx.send(job).map_err(|err| err.to_string())
    }

    fn decrypt(&mut self, tx: &Sender<()>) -> Result<Vec<u8>,String> {
        let mut cursor = self.recv_buf.lock().unwrap();
        let plain_bytes = cursor.clone().into_inner().to_vec();
        *cursor = Cursor::new(Vec::new());
        tx.send(()).map_err(|err| err.to_string())?;
        Ok(plain_bytes)
    }

    fn new(nonce: box_::Nonce, pipe: Pipe<BufTcpStream>, pub_key: &box_::PublicKey, sec_key: &box_::SecretKey) -> Conn {
        let pre_key = box_::precompute(pub_key, sec_key);
        let recv_buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let send_buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        Conn{
            nonce,
            pipe,
            pre_key,
            recv_buf,
            send_buf,
        }
    }

    fn send_handshake(&mut self, alias: &str) -> Result<(),String> {
        let mut handshake = self.pipe.key.0.to_vec();
        handshake.extend_from_slice(&self.pipe.nonce.0);
        handshake.extend_from_slice(alias.as_bytes());
        let handshake = box_::seal_precomputed(&handshake, &self.nonce, &self.pre_key);
        self.write_u32::<BigEndian>(handshake.len() as u32).map_err(|err| err.to_string())?;
        self.write_all(&handshake).map_err(|err| err.to_string())?;
        self.flush().map_err(|err| err.to_string())
    }

    fn recv_handshake(&mut self) -> Result<String,String> {
        let handshake_size = self.read_u32::<BigEndian>().map_err(|err| err.to_string())?;
        let mut handshake = vec![0u8; handshake_size as usize];
        self.read_exact(&mut handshake).map_err(|err| err.to_string())?;
        let handshake = box_::open_precomputed(&handshake, &self.nonce, &self.pre_key).unwrap();
        self.pipe.key = secretbox::Key::from_slice(&handshake[..secretbox::KEYBYTES]).unwrap();
        self.pipe.nonce = secretbox::Nonce::from_slice(&handshake[secretbox::KEYBYTES..secretbox::KEYBYTES+secretbox::NONCEBYTES]).unwrap();
        let alias = String::from_utf8(handshake[secretbox::KEYBYTES+secretbox::NONCEBYTES..].to_vec()).map_err(|err| err.to_string())?;
        Ok(alias)
    } 

    fn encrypt_routine(mut pipe: Pipe<BufTcpStream>, rx: Receiver<Job>, send_buf: Arc<Mutex<Cursor<Vec<u8>>>>) -> Result<(),String> {
        loop {
            let Job{chunk_size, file_size, mime} = rx.recv().map_err(|err| err.to_string())?;
            let mut cursor = send_buf.lock().unwrap();
            pipe.encrypt(chunk_size, file_size, mime, &mut *cursor)?;
            cursor.set_position(0);
        }
    }

    fn decrypt_routine(mut pipe: Pipe<BufTcpStream>, rx: Receiver<()>, recv_buf: Arc<Mutex<Cursor<Vec<u8>>>>) -> Result<(),String> {
        loop {
            {
                let mut cursor = recv_buf.lock().unwrap();
                pipe.decrypt(&mut *cursor)?;
                cursor.set_position(0);
            }
            rx.recv().map_err(|err| err.to_string())?;
        }
    }

    fn run(&self) -> (Sender<()>,Sender<Job>) {
        let pipe1 = self.pipe.clone();
        let pipe2 = self.pipe.clone();
        let recv_buf = self.recv_buf.clone();
        let send_buf = self.send_buf.clone();
        let (txd, rxd) = channel();
        let (txe, rxe) = channel();
        thread::spawn(move || Conn::decrypt_routine(pipe1, rxd, recv_buf));
        thread::spawn(move || Conn::encrypt_routine(pipe2, rxe, send_buf));
        (txd, txe)
    }
}

#[derive(Debug)]
pub struct Conn_ {
    conn: Conn,
    txd: Sender<()>,
    txe: Sender<Job>,
}

impl PartialEq for Conn_ {
    fn eq(&self, other: &Self) -> bool {
        self.conn == other.conn
    }
}

#[derive(Debug)]
pub struct Hub {
    alias: String,
    conns: Arc<Mutex<HashMap<String,Conn_>>>,
    listener: TcpListener,
    nonce: box_::Nonce,
    pub_key: box_::PublicKey,
    sec_key: box_::SecretKey,
}

impl Hub {

    pub fn new(addr: &str, alias: &str, pub_key: box_::PublicKey, sec_key: box_::SecretKey) -> Hub {
        let alias = alias.to_owned();
        let conns = Arc::new(Mutex::new(HashMap::new()));
        let listener = TcpListener::bind(addr).unwrap();
        let nonce = box_::gen_nonce();
        Hub{
            alias,
            conns,
            listener,
            nonce,
            pub_key,
            sec_key,
        }
    }

    pub fn decrypt(&mut self, alias: &str) -> Result<Vec<u8>,String> {
        let mut conns = self.conns.lock().unwrap();
        if let Some(conn) = conns.get_mut(alias) {
            conn.conn.decrypt(&conn.txd)
        } else {
            Err(format!("Hub does not have conn with alias='{}'", alias))
        }
    }

    pub fn encrypt<R: Read>(&mut self, alias: &str, chunk_size: u32, mime: String, r: &mut R) -> Result<(),String> {
        let mut conns = self.conns.lock().unwrap();
        if let Some(conn) = conns.get_mut(alias) {
            conn.conn.encrypt(chunk_size, mime, r, &conn.txe)
        } else {
            Err(format!("Hub does not have conn with alias='{}'", alias))
        }
    }

    pub fn run(&self) -> Result<(),String> {
        let alias = self.alias.clone();
        let conns = self.conns.clone();
        let listener = self.listener.try_clone().map_err(|err| err.to_string())?;
        thread::spawn(move || {
            loop {
                Hub::accept(&alias, &conns, &listener).unwrap();
            }
        });
        Ok(())
    }

    fn accept(alias: &str, conns: &Arc<Mutex<HashMap<String,Conn_>>>, listener: &TcpListener) -> Result<(),String> {
        let (stream, _) = listener.accept().map_err(|err| err.to_string())?;
        let mut stream = BufTcpStream::new(stream);
        let (pk, sec_key) = box_::gen_keypair();
        stream.write_all(&pk.0).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())?;
        let handshake_size = stream.read_u32::<BigEndian>().map_err(|err| err.to_string())?;
        let mut handshake = vec![0u8; handshake_size as usize];
        stream.read_exact(&mut handshake).map_err(|err| err.to_string())?;
        let handshake = sealedbox::open(&handshake, &pk, &sec_key).unwrap();
        let pub_key = box_::PublicKey::from_slice(&handshake[..box_::PUBLICKEYBYTES]).unwrap();
        let nonce = box_::Nonce::from_slice(&handshake[box_::PUBLICKEYBYTES..box_::PUBLICKEYBYTES+box_::NONCEBYTES]).unwrap();
        let alias_ = String::from_utf8(handshake[box_::PUBLICKEYBYTES+box_::NONCEBYTES..].to_vec()).map_err(|err| err.to_string())?;
        let mut conns = conns.lock().unwrap();
        if conns.contains_key(&alias_) {
            return Err(format!("Hub already has conn with alias='{}'", alias_))
        }
        let pipe = Pipe::new(stream);
        let mut conn = Conn::new(nonce, pipe, &pub_key, &sec_key);
        conn.send_handshake(alias)?;
        let (txd, txe) = conn.run();
        let conn = Conn_{conn, txd, txe};
        conns.insert(alias_, conn);
        Ok(())
    }

    pub fn connect(&mut self, addr: &str) -> Result<(),String> {
        let stream = TcpStream::connect(addr).map_err(|err| err.to_string())?;
        let mut stream = BufTcpStream::new(stream);
        let mut pub_key = vec![0u8; box_::PUBLICKEYBYTES];
        stream.read_exact(&mut pub_key).map_err(|err| err.to_string())?;
        let pub_key = box_::PublicKey::from_slice(&pub_key).unwrap();
        let mut handshake = self.pub_key.0.to_vec();
        handshake.extend_from_slice(&self.nonce.0);
        handshake.extend_from_slice(self.alias.as_bytes());
        let handshake = sealedbox::seal(&handshake, &pub_key);
        stream.write_u32::<BigEndian>(handshake.len() as u32).map_err(|err| err.to_string())?;
        stream.write_all(&handshake).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())?;
        let pipe = Pipe::new(stream);
        let mut conn = Conn::new(self.nonce.clone(), pipe, &pub_key, &self.sec_key);
        let alias = conn.recv_handshake()?;
        let mut conns = self.conns.lock().unwrap();
        if conns.contains_key(&alias) {
            return Err(format!("Hub already has conn with alias='{}'", alias))
        }
        let (txd, txe) = conn.run();
        let conn = Conn_{conn, txd, txe};
        conns.insert(alias, conn);
        Ok(())
    }
}

mod example {

    use super::*;

    use std::fs::File;
    use std::io::Cursor;

    pub fn pipe() {

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

    pub fn conn() {

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

    fn get_plain_bytes() -> Vec<u8> {
        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len() as usize;
        let mut plain_bytes = vec![0u8; file_size];
        file.read_exact(&mut plain_bytes).unwrap();
        plain_bytes
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

        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len() as u32;
        let mime = "audio/mp3".to_owned();
        let header = header(chunk_size, file_size, mime.clone());

        let cipher = Cursor::new(Vec::new());
        let mut pipe = Pipe::new(cipher);

        let hdr = pipe.encrypt(chunk_size, file_size, "audio/mp3".to_owned(), &mut file).unwrap();
        assert_eq!(header, hdr);
        pipe.cipher.set_position(0);

        let mut decrypted = Cursor::new(Vec::new());
        let hdr = pipe.decrypt(&mut decrypted).unwrap();
        assert_eq!(header, hdr);  

        let plain_bytes = get_plain_bytes();
        let decrypted_bytes = decrypted.into_inner();

        assert_eq!(plain_bytes, decrypted_bytes);
    }

    fn test_pipes(chunk_size1: u32, chunk_size2: u32) {

        let mut file = File::open("test.mp3").unwrap();
        let mime = "audio/mp3".to_owned();
        let file_size1 = file.metadata().unwrap().len() as u32;
        let file_size2 = total_encrypted_size(chunk_size1, file_size1, mime.clone());

        let header1 = header(chunk_size1, file_size1, mime.clone());
        let header2 = header(chunk_size2, file_size2, String::new());

        let cipher = Cursor::new(Vec::new());
        let mut pipe = Pipe::new(cipher);

        let hdr = pipe.encrypt(chunk_size1, file_size1, mime, &mut file).unwrap();
        assert_eq!(header1, hdr);
        pipe.cipher.set_position(0); 
        
        let hdr = pipe.encrypt_self(chunk_size2, file_size2, String::new()).unwrap();
        assert_eq!(header2, hdr);
        pipe.cipher.set_position(0);

        let hdr = pipe.decrypt_self().unwrap();
        assert_eq!(header2, hdr);
        pipe.cipher.set_position(0);

        let mut decrypted = Cursor::new(Vec::new());
        let hdr = pipe.decrypt(&mut decrypted).unwrap();
        assert_eq!(header1, hdr); 

        let plain_bytes = get_plain_bytes();
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

    #[test]
    fn test_conn() {

        let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
        let handle = thread::spawn(|| {
            TcpStream::connect("127.0.0.1:12345").unwrap()
        });

        let (server_stream, _) = listener.accept().unwrap();
        let client_stream = handle.join().unwrap();

        let nonce = box_::gen_nonce();
        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, server_sk) = box_::gen_keypair();

        let client_cipher = BufTcpStream::new(client_stream);
        let client_pipe = Pipe::new(client_cipher);
        let mut client_conn = Conn::new(nonce, client_pipe, &server_pk, &client_sk);

        let server_cipher = BufTcpStream::new(server_stream);
        let server_pipe = Pipe::new(server_cipher);
        let mut server_conn = Conn::new(nonce, server_pipe, &client_pk, &server_sk);

        let alias = "george_costanza".to_owned();

        client_conn.send_handshake(&alias).unwrap();
        assert_eq!(alias, server_conn.recv_handshake().unwrap());

        assert_eq!(client_conn.pipe.key, server_conn.pipe.key);
        assert_eq!(client_conn.pipe.nonce, server_conn.pipe.nonce);

        let (_, client_txe) = client_conn.run();
        let (server_txd, _) = server_conn.run();

        let mut file = File::open("test.mp3").unwrap();
        client_conn.encrypt(DEFAULT_CHUNK_SIZE, "audio/mp3".to_owned(), &mut file, &client_txe).unwrap();
        
        let decrypted_bytes = server_conn.decrypt(&server_txd).unwrap();
        let plain_bytes = get_plain_bytes();

        assert_eq!(decrypted_bytes, plain_bytes);
    }
    
    #[test]
    fn test_hub() {

        let addr1 = "127.0.0.1:54320";
        let addr2 = "127.0.0.1:54321";
        let addr3 = "127.0.0.1:10080";

        let alias1 = "hub1";
        let alias2 = "hub2";
        let alias3 = "hub3";

        let (pub_key1, sec_key1) = box_::gen_keypair();
        let (pub_key2, sec_key2) = box_::gen_keypair();
        let (pub_key3, sec_key3) = box_::gen_keypair();

        let mut hub1 = Hub::new(addr1, alias1, pub_key1, sec_key1);
        let mut hub2 = Hub::new(addr2, alias2, pub_key2, sec_key2);
        let mut hub3 = Hub::new(addr3, alias3, pub_key3, sec_key3);

        hub1.run().unwrap();
        hub2.run().unwrap();

        hub1.connect(addr2).unwrap();

        assert_eq!(1, hub1.conns.lock().unwrap().len());
        assert_eq!(1, hub2.conns.lock().unwrap().len());

        {   
            let conns1 = hub1.conns.lock().unwrap();
            let conns2 = hub2.conns.lock().unwrap();
            let conn1 = conns1.get(alias2);
            let conn2 = conns2.get(alias1);
            assert_eq!(conn1, conn2);
        }

        let mut file = File::open("test.mp3").unwrap();
        let mime = "audio/mp3".to_owned();

        hub1.encrypt(alias2, DEFAULT_CHUNK_SIZE, mime, &mut file).unwrap();

        let plain_bytes = get_plain_bytes();
        let decrypted_bytes = hub2.decrypt(alias1).unwrap();

        assert_eq!(plain_bytes, decrypted_bytes);

        hub3.run().unwrap();
        hub1.connect(addr3).unwrap();
        hub2.connect(addr3).unwrap();

        assert_eq!(2, hub1.conns.lock().unwrap().len());
        assert_eq!(2, hub2.conns.lock().unwrap().len());
        assert_eq!(2, hub3.conns.lock().unwrap().len());

        assert!(hub2.connect(addr1).is_err());
    }
}