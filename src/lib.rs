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
    decrypt_nonce: secretbox::Nonce,
    encrypt_nonce: secretbox::Nonce,
    first_decrypt_nonce: secretbox::Nonce,
    first_encrypt_nonce: secretbox::Nonce,
    key: secretbox::Key,
}

impl<C: Clone + Read + Write> PartialEq for Pipe<C> {
    fn eq(&self, other: &Self) -> bool {
        self.decrypt_nonce == other.encrypt_nonce &&
        self.encrypt_nonce == other.decrypt_nonce &&
        self.first_decrypt_nonce == other.first_encrypt_nonce &&
        self.first_encrypt_nonce == other.first_decrypt_nonce &&
        self.key == other.key
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
        let decrypt_nonce = secretbox::gen_nonce();
        let encrypt_nonce = secretbox::gen_nonce();
        let first_decrypt_nonce = decrypt_nonce.clone();
        let first_encrypt_nonce = encrypt_nonce.clone();
        let key = secretbox::gen_key();
        Pipe{
            cipher,
            decrypt_nonce,
            encrypt_nonce,
            first_decrypt_nonce,
            first_encrypt_nonce,
            key,
        }
    }

    pub fn decrypt<W: Write>(&mut self, w: &mut W) -> Result<Header,String> {
        self.decrypt_nonce.increment_le_inplace();
        if self.decrypt_nonce == self.first_decrypt_nonce {
            return Err("Cannot decrypt with pipe anymore".to_owned())
        }
        let header = Header::decrypt(&self.key, &self.decrypt_nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        let mut frame = vec![0u8; header.frame_size as usize];
        let mut size_left = header.encrypted_body_size;
        while size_left > header.frame_size {
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = &secretbox::open(&frame, &self.decrypt_nonce, &self.key).unwrap();
            w.write_all(&chunk).map_err(|err| err.to_string())?;
            size_left -= header.frame_size;
        }
        if size_left > 0 {
            if size_left < header.frame_size {
                frame.truncate(size_left as usize);
            }
            self.read_exact(&mut frame).map_err(|err| err.to_string())?;
            let chunk = secretbox::open(&frame, &self.decrypt_nonce, &self.key).unwrap();
            w.write_all(&chunk).map_err(|err| err.to_string())?;
        }
        self.flush().map_err(|err| err.to_string())?;
        Ok(header)
    }

    pub fn encrypt<R: Read>(&mut self, chunk_size: u32, file_size: u32, mime: String, r: &mut R) -> Result<Header,String> {
        self.encrypt_nonce.increment_le_inplace();
        if self.encrypt_nonce == self.first_encrypt_nonce {
            println!("HERE");
            return Err("Cannot encrypt with pipe anymore".to_owned())
        }
        let mut chunk = vec![0u8; chunk_size as usize];
        let header = header(chunk_size, file_size, mime);
        let mut size_left = file_size;
        header.encrypt(&self.key, &self.encrypt_nonce, &mut self.cipher).map_err(|err| err.to_string())?;
        while size_left > chunk_size {
            r.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.encrypt_nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
            size_left -= chunk_size;
        } 
        if size_left > 0 {
            if size_left < chunk_size {
                chunk.truncate(size_left as usize);
            }
            r.read_exact(&mut chunk).map_err(|err| err.to_string())?;
            let frame = secretbox::seal(&chunk, &self.encrypt_nonce, &self.key);
            self.write_all(&frame).map_err(|err| err.to_string())?;
        }
        self.flush().map_err(|err| err.to_string())?;
        Ok(header)
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
    pipe: Pipe<BufTcpStream>,
    pre_key: box_::PrecomputedKey,
    recv_buf: Arc<Mutex<Cursor<Vec<u8>>>>,
    send_buf: Arc<Mutex<Cursor<Vec<u8>>>>,
}

impl PartialEq for Conn {
    fn eq(&self, other: &Self) -> bool {
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

    fn new(pipe: Pipe<BufTcpStream>, pub_key: &box_::PublicKey, sec_key: &box_::SecretKey) -> Conn {
        let pre_key = box_::precompute(pub_key, sec_key);
        let recv_buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let send_buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        Conn{
            pipe,
            pre_key,
            recv_buf,
            send_buf,
        }
    }

    fn connect(&mut self, alias: &str, nonce: &box_::Nonce) -> Result<(),String> {
        let mut handshake = self.pipe.key.0.to_vec();
        handshake.extend_from_slice(&self.pipe.encrypt_nonce.0);
        handshake.extend_from_slice(&self.pipe.decrypt_nonce.0);
        handshake.extend_from_slice(alias.as_bytes());
        let handshake = box_::seal_precomputed(&handshake, nonce, &self.pre_key);
        self.write_u32::<BigEndian>(handshake.len() as u32).map_err(|err| err.to_string())?;
        self.write_all(&handshake).map_err(|err| err.to_string())?;
        self.flush().map_err(|err| err.to_string())
    }

    fn accept(&mut self, nonce: &box_::Nonce) -> Result<String,String> {
        let handshake_size = self.read_u32::<BigEndian>().map_err(|err| err.to_string())?;
        let mut handshake = vec![0u8; handshake_size as usize];
        self.read_exact(&mut handshake).map_err(|err| err.to_string())?;
        let handshake = box_::open_precomputed(&handshake, nonce, &self.pre_key).unwrap();
        self.pipe.key = secretbox::Key::from_slice(&handshake[..secretbox::KEYBYTES]).unwrap();
        self.pipe.decrypt_nonce = secretbox::Nonce::from_slice(&handshake[secretbox::KEYBYTES..secretbox::KEYBYTES+secretbox::NONCEBYTES]).unwrap();
        self.pipe.encrypt_nonce = secretbox::Nonce::from_slice(&handshake[secretbox::KEYBYTES+secretbox::NONCEBYTES..secretbox::KEYBYTES+2*secretbox::NONCEBYTES]).unwrap();
        self.pipe.first_decrypt_nonce = self.pipe.decrypt_nonce.clone();
        self.pipe.first_encrypt_nonce = self.pipe.encrypt_nonce.clone();
        let alias = String::from_utf8(handshake[secretbox::KEYBYTES+2*secretbox::NONCEBYTES..].to_vec()).map_err(|err| err.to_string())?;
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
    addr: String,
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
        let addr = addr.to_owned();
        let nonce = box_::gen_nonce();
        Hub{
            addr,
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
        let mut conn = Conn::new(pipe, &pub_key, &sec_key);
        conn.connect(alias, &nonce)?;
        let (txd, txe) = conn.run();
        let conn = Conn_{conn, txd, txe};
        conns.insert(alias_, conn);
        Ok(())
    }

    pub fn connect(&mut self, addr: &str) -> Result<(),String> {
        self.nonce.increment_le_inplace();
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
        let mut conn = Conn::new(pipe, &pub_key, &self.sec_key);
        let alias = conn.accept(&self.nonce)?;
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

        // open file
        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len() as u32;
        let mime = "audio/mp3".to_owned();

        // read plain bytes
        let mut plain_bytes = vec![0u8; file_size as usize];
        file.read_exact(&mut plain_bytes).unwrap();

        // new pipe
        let cipher = Cursor::new(Vec::new());
        let mut pipe = Pipe::new(cipher);
        pipe.encrypt_nonce = pipe.decrypt_nonce;
        pipe.first_encrypt_nonce = pipe.first_decrypt_nonce;

        // encrypt 
        pipe.encrypt(DEFAULT_CHUNK_SIZE, file_size, mime, &mut plain_bytes.as_slice()).unwrap();
        pipe.cipher.set_position(0);

        // decrypt
        let mut decrypted_bytes = Vec::new();
        pipe.decrypt(&mut decrypted_bytes).unwrap();

        // compare decrypted bytes to plain bytes
        assert_eq!(plain_bytes, decrypted_bytes);
    }

    pub fn conn() {

        // generate nonce and keypairs
        let nonce = box_::gen_nonce();
        let (pk1, sk1) = box_::gen_keypair();
        let (pk2, sk2) = box_::gen_keypair();

        // create tcp streams
        let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
        let handle = thread::spawn(|| TcpStream::connect("127.0.0.1:12345").unwrap());
        let (stream1, _) = listener.accept().unwrap();
        let stream2 = handle.join().unwrap();

        // create conns
        let pipe1 = Pipe::new(BufTcpStream::new(stream1));
        let pipe2 = Pipe::new(BufTcpStream::new(stream2));
        let mut conn1 = Conn::new(pipe1, &pk2, &sk1);
        let mut conn2 = Conn::new(pipe2, &pk1, &sk2);

        // connect conns
        let alias = "conn1".to_owned();
        conn1.connect(&alias, &nonce).unwrap();
        conn2.accept(&nonce).unwrap();

        // run conns
        let (_, txe) = conn1.run();
        let (txd, _) = conn2.run();

        // open file
        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len() as u32;
        let mime = "audio/mp3".to_owned();

        // read plain bytes
        let mut plain_bytes = vec![0u8; file_size as usize];
        file.read_exact(&mut plain_bytes).unwrap();

        // conn1 encrypts, conn2 decrypts
        conn1.encrypt(DEFAULT_CHUNK_SIZE, mime, &mut plain_bytes.as_slice(), &txe).unwrap();
        let decrypted_bytes = conn2.decrypt(&txd).unwrap();

        // compare decrypted bytes to plain bytes
        assert_eq!(decrypted_bytes, plain_bytes);
    }

    pub fn hub() {

        // generate keypairs
        let (pub_key1, sec_key1) = box_::gen_keypair();
        let (pub_key2, sec_key2) = box_::gen_keypair();

        // create hubs
        let mut hub1 = Hub::new("127.0.0.1:10000", "hub1", pub_key1, sec_key1);
        let mut hub2 = Hub::new("127.0.0.1:20000", "hub2", pub_key2, sec_key2);

        // run hubs and connect them
        hub1.run().unwrap();
        hub2.run().unwrap();
        hub1.connect(&hub2.addr).unwrap();

        // open file
        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len();
        let mime = "audio/mp3".to_owned();

        // read plain bytes 
        let mut plain_bytes = vec![0u8; file_size as usize];
        file.read_exact(&mut plain_bytes).unwrap();

        // hub1 encrypts, hub2 decrypts
        hub1.encrypt(&hub2.alias, DEFAULT_CHUNK_SIZE, mime, &mut plain_bytes.as_slice()).unwrap();
        let decrypted_bytes = hub2.decrypt(&hub1.alias).unwrap();

        // compare decrypted bytes to plain bytes
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

    fn mime() -> String {
        "audio/mp3".to_owned()
    }

    fn gen_key_nonce() -> (secretbox::Key,secretbox::Nonce) {
        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        (key, nonce)
    }

    fn new_header() -> Header {
        let encrypted_body_size = 49225 + secretbox::MACBYTES as u32;
        let frame_size = DEFAULT_CHUNK_SIZE + secretbox::MACBYTES as u32;
        let mime = mime();
        let num_frames = 4;
        Header{
            encrypted_body_size,
            frame_size,
            mime,
            num_frames,
        }
    }

    fn read_file() -> (Vec<u8>, u32) {
        let mut file = File::open("test.mp3").unwrap();
        let file_size = file.metadata().unwrap().len();
        let mut file_bytes = vec![0u8; file_size as usize];
        file.read_exact(&mut file_bytes).unwrap();
        (file_bytes, file_size as u32)
    }

    fn new_pipe() -> Pipe<Cursor<Vec<u8>>> {
        let cipher = Cursor::new(Vec::new());
        let mut pipe = Pipe::new(cipher);
        pipe.encrypt_nonce = pipe.decrypt_nonce;
        pipe.first_encrypt_nonce = pipe.first_decrypt_nonce;
        pipe 
    }

    fn encrypt_and_decrypt_with_pipe(chunk_size: u32, file_bytes: &Vec<u8>, file_size: u32, pipe: &mut Pipe<Cursor<Vec<u8>>>) -> (Header,Vec<u8>) {

        pipe.encrypt(chunk_size, file_size, mime(), &mut file_bytes.as_slice()).unwrap();
        pipe.cipher.set_position(0);

        let mut decrypted_bytes = Vec::new();
        let header = pipe.decrypt(&mut decrypted_bytes).unwrap();
        pipe.cipher.set_position(0);

        (header,decrypted_bytes)
    }

    fn check_header(actual: Header, chunk_size: u32, file_size: u32) {
        let expected = header(chunk_size, file_size, mime());
        assert_eq!(expected, actual);
    }

    fn check_decrypted_bytes(file_bytes: &[u8], decrypted_bytes: &[u8]) {
        assert_eq!(file_bytes, decrypted_bytes);
    }

    fn check_pipe_nonces(pipe: &mut Pipe<Cursor<Vec<u8>>>, decrypt_nonce: &mut secretbox::Nonce, encrypt_nonce: &mut secretbox::Nonce) {
        decrypt_nonce.increment_le_inplace();
        encrypt_nonce.increment_le_inplace();
        assert_eq!(decrypt_nonce, &mut pipe.decrypt_nonce);
        assert_eq!(encrypt_nonce, &mut pipe.encrypt_nonce);
    }

    fn new_conns() -> (Conn,Conn) {

        let listener = TcpListener::bind("127.0.0.1:12345").unwrap();

        let handle = thread::spawn(|| {
            TcpStream::connect("127.0.0.1:12345").unwrap()
        });

        let (stream1, _) = listener.accept().unwrap();
        let stream2 = handle.join().unwrap();

        let (pk1, sk1) = box_::gen_keypair();
        let (pk2, sk2) = box_::gen_keypair();

        let cipher1 = BufTcpStream::new(stream1);
        let pipe1 = Pipe::new(cipher1);
        let conn1 = Conn::new(pipe1, &pk2, &sk1);

        let cipher2 = BufTcpStream::new(stream2);
        let pipe2 = Pipe::new(cipher2);
        let conn2 = Conn::new(pipe2, &pk1, &sk2);

        (conn1,conn2)
    }

    fn connect_conns(conn1: &mut Conn, conn2: &mut Conn, nonce: &box_::Nonce) -> (Sender<()>,Sender<Job>) {

        let alias = "george_costanza".to_owned();

        conn1.connect(&alias, nonce).unwrap();
        let res = conn2.accept(nonce).unwrap();

        assert_eq!(alias, res);
        assert_eq!(conn1, conn2);

        let (_, txe) = conn1.run();
        let (txd, _) = conn2.run();

        (txd, txe)
    }

    fn encrypt_and_decrypt_with_conns(conn1: &mut Conn, conn2: &mut Conn, chunk_size: u32, file_bytes: &Vec<u8>, txd: &Sender<()>, txe: &Sender<Job>) -> Vec<u8> {
        conn1.encrypt(chunk_size, mime(), &mut file_bytes.as_slice(), txe).unwrap();
        conn2.decrypt(txd).unwrap()
    }

    fn new_hub(addr: &str, alias: &str) -> Hub {
        let (pub_key, sec_key) = box_::gen_keypair();
        let hub = Hub::new(addr, alias, pub_key, sec_key);
        hub.run().unwrap();
        hub
    }

    fn connect_hubs(hub1: &mut Hub, hub2: &mut Hub) {

        hub1.connect(&hub2.addr).unwrap();

        let conns1 = hub1.conns.lock().unwrap();
        let conns2 = hub2.conns.lock().unwrap();

        let conn1 = conns1.get(&hub2.alias);
        let conn2 = conns2.get(&hub1.alias);
        
        assert_eq!(conn1, conn2);
    }
    
    fn encrypt_and_decrypt_with_hubs(hub1: &mut Hub, hub2: &mut Hub, chunk_size: u32, file_bytes: &Vec<u8>) -> Vec<u8> {
        hub1.encrypt(&hub2.alias, chunk_size, mime(), &mut file_bytes.as_slice()).unwrap();
        hub2.decrypt(&hub1.alias).unwrap()
    }

    fn try_to_connect_hubs_again(hub1: &mut Hub, hub2: &mut Hub) {
        assert!(hub1.connect(&hub2.addr).is_err());
        assert!(hub2.connect(&hub1.addr).is_err());
    }

    fn check_hub_nonce(hub: &mut Hub, nonce: &mut box_::Nonce) {
        nonce.increment_le_inplace();
        assert_eq!(nonce, &mut hub.nonce);
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
        assert_eq!(header, Header::decrypt(&key, &nonce, &mut rw).unwrap());
    }

    #[test]
    fn test_pipe() {

        let mut pipe = new_pipe();
        let (file_bytes, file_size) = read_file();

        let mut decrypt_nonce = pipe.decrypt_nonce.clone();
        let mut encrypt_nonce = pipe.encrypt_nonce.clone();

        let (header,decrypted_bytes) = encrypt_and_decrypt_with_pipe(DEFAULT_CHUNK_SIZE, &file_bytes, file_size, &mut pipe);
        check_header(header, DEFAULT_CHUNK_SIZE, file_size);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);
        check_pipe_nonces(&mut pipe, &mut decrypt_nonce, &mut encrypt_nonce);

        let (header,decrypted_bytes) = encrypt_and_decrypt_with_pipe(ALTERNATE_CHUNK_SIZE, &file_bytes, file_size, &mut pipe);
        check_header(header, ALTERNATE_CHUNK_SIZE, file_size);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);
        check_pipe_nonces(&mut pipe, &mut decrypt_nonce, &mut encrypt_nonce);

        example::pipe();
    }

    #[test]
    fn test_conn() {

        let (mut conn1, mut conn2) = new_conns();
        let (file_bytes, _) = read_file();
        let nonce = box_::gen_nonce();

        let (txd, txe) = connect_conns(&mut conn1, &mut conn2, &nonce);

        let decrypted_bytes = encrypt_and_decrypt_with_conns(&mut conn1, &mut conn2, DEFAULT_CHUNK_SIZE, &file_bytes, &txd, &txe);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);

        let decrypted_bytes = encrypt_and_decrypt_with_conns(&mut conn1, &mut conn2, ALTERNATE_CHUNK_SIZE, &file_bytes, &txd, &txe);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);
        
        example::conn();
    }

    #[test]
    fn test_hub() {

        let mut hub1 = new_hub("127.0.0.1:11111", "hub1");
        let mut hub2 = new_hub("127.0.0.1:22222", "hub2");
        let mut hub3 = new_hub("127.0.0.1:33333", "hub3");

        let mut nonce = hub1.nonce.clone();

        let (file_bytes, _) = read_file();

        connect_hubs(&mut hub1, &mut hub2);
        check_hub_nonce(&mut hub1, &mut nonce);

        connect_hubs(&mut hub1, &mut hub3);
        check_hub_nonce(&mut hub1, &mut nonce);

        let decrypted_bytes = encrypt_and_decrypt_with_hubs(&mut hub1, &mut hub2, DEFAULT_CHUNK_SIZE, &file_bytes);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);

        let decrypted_bytes = encrypt_and_decrypt_with_hubs(&mut hub1, &mut hub3, ALTERNATE_CHUNK_SIZE, &file_bytes);
        check_decrypted_bytes(&file_bytes, &decrypted_bytes);

        try_to_connect_hubs_again(&mut hub1, &mut hub2);

        example::hub();
    }

    /*

    #[bench]
    fn bench_pipe(b: &mut Bencher) {
        let (file_bytes, file_size) = read_file();
        let mut pipe = new_pipe();
        b.iter(|| encrypt_and_decrypt_with_pipe(DEFAULT_CHUNK_SIZE, &file_bytes, file_size, &mut pipe));
    }

    #[bench]
    fn bench_conn(b: &mut Bencher) {
        let (file_bytes, _) = read_file();
        let (mut conn1, mut conn2) = new_conns();
        let nonce = box_::gen_nonce();
        let (txd, txe) = connect_conns(&mut conn1, &mut conn2, &nonce);
        b.iter(|| encrypt_and_decrypt_with_conns(&mut conn1, &mut conn2, DEFAULT_CHUNK_SIZE, &file_bytes, &txd, &txe));
    }

    #[bench]
    fn bench_hub(b: &mut Bencher) {
        let (file_bytes, _) = read_file();
        let (mut hub1, mut hub2) = new_hubs();
        connect_hubs(&mut hub1, &mut hub2);
        b.iter(|| encrypt_and_decrypt_with_hubs(&mut hub1, &mut hub2, DEFAULT_CHUNK_SIZE, &file_bytes));
    }

    */
}