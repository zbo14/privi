## privi

### Pipe

example:

```rust 
use std::fs::File;
use std::io::Cursor;
use sodiumoxide::secretbox::{gen_key,gen_nonce};

fn main() {

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
```

### Conn

example:

```rust
use std::fs::File;
use std::net::{TcpListener,TcpStream};
use std::thread;
use sodiumoxide::box_::{gen_keypair,gen_nonce};

fn main() {

    // generate nonce and keypairs
    let nonce = gen_nonce();
    let (pk1, sk1) = gen_keypair();
    let (pk2, sk2) = gen_keypair();

    // create tcp streams
    let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
    let handle = thread::spawn(|| TcpStream::connect("127.0.0.1:12345").unwrap());
    let (stream1, _) = listener.accept().unwrap();
    let stream2 = handle.join().unwrap();

    // create conns
    let pipe1 = Pipe::new(BufTcpStream::new(stream1));
    let pipe2 = Pipe::new(BufTcpStream::new(stream2));
    let mut conn1 = Conn::new(nonce, pipe1, &pk2, &sk1);
    let mut conn2 = Conn::new(nonce, pipe2, &pk1, &sk2);

    // connect conns
    let alias = "conn1".to_owned();
    conn1.connect(&alias).unwrap();
    conn2.accept().unwrap();

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
```

### Hub 

example: 

```rust
use std::fs::File;
use sodiumoxide::box_::gen_keypair;

fn main() {

    // generate keypairs
    let (pub_key1, sec_key1) = gen_keypair();
    let (pub_key2, sec_key2) = gen_keypair();

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
```