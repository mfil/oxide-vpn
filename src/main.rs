extern crate openssl;
extern crate rand;

use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread;

use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::rng;

mod control_channel;
mod packets;
mod retransmit;

use control_channel::ControlChannel;
use packets::{ControlChannelPacket, Packet};

#[derive(Debug)]
struct E {}

impl fmt::Display for E {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl Error for E {}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");
    let args = std::vec::Vec::from_iter(env::args());
    if args.len() < 6 {
        return Result::Err(Box::new(E {}));
    }
    let socket = UdpSocket::bind(("127.0.0.1", 50000))?;
    let address = &args[1][..];
    let port = u16::from_str_radix(&args[2], 10)?;
    let ca_path = Path::new(&args[3]);
    let cert_path = Path::new(&args[4]);
    let key_path = Path::new(&args[5]);

    let mut ca_file = File::open(ca_path)?;
    let mut ca_pem = Vec::new();
    let _ = ca_file.read_to_end(&mut ca_pem);

    let mut cert_file = File::open(cert_path)?;
    let mut cert_pem = Vec::new();
    let _ = cert_file.read_to_end(&mut cert_pem);

    let mut key_file = File::open(key_path)?;
    let mut key_pem = Vec::new();
    let _ = key_file.read_to_end(&mut key_pem);

    socket.connect((address, port))?;
    println!("Connected to {}:{}", &args[1][..], port);

    let (incoming_send, control_receive) = channel::<ControlChannelPacket>();
    let (control_send, outgoing_receive) = channel();

    let mut control_channel = ControlChannel::new(
        &mut rng(),
        false,
        X509::from_pem(&ca_pem)?,
        X509::from_pem(&cert_pem)?,
        PKey::private_key_from_pem(&key_pem)?,
        control_receive,
        control_send,
    );

    let socket_read = socket.try_clone()?;
    let socket_read_thread = thread::spawn(move || -> std::io::Result<()> {
        let socket = socket_read;
        let mut read_buffer: [u8; 3000] = [0; 3000];
        let send_channel = incoming_send;
        while !SHUTDOWN.load(Ordering::Relaxed) {
            let length = socket.recv(&mut read_buffer)?;
            let packet = Packet::parse(&read_buffer[..length]).unwrap();
            if let Packet::Control(p) = packet {
                send_channel.send(p).unwrap();
            }
        }
        Ok(())
    });

    let socket_write_thread = thread::spawn(move || -> std::io::Result<()> {
        let socket = socket;
        let mut write_buffer: [u8; 3000] = [0; 3000];
        let receive_channel = outgoing_receive;
        while !SHUTDOWN.load(Ordering::Relaxed) {
            let packet = receive_channel.recv().unwrap();
            let length = packet.to_buffer(&mut write_buffer).unwrap();
            socket.send(&write_buffer[..length])?;
        }
        Ok(())
    });

    let mut read_buffer: [u8; 3000] = [0; 3000];
    let mut count = 0;
    while !SHUTDOWN.load(Ordering::Relaxed) {
        if let Ok(length) = control_channel.write(b"Hello") {
            println!("Wrote {} bytes", length);
        }
        if let Ok(length) = control_channel.read(&mut read_buffer) {
            println!("{:?}", &read_buffer[..length]);
        }
        thread::sleep(std::time::Duration::from_secs(3));
        if count > 10 {
            SHUTDOWN.store(true, Ordering::Relaxed);
        }
        count += 1;
    }

    socket_write_thread.join().unwrap()?;
    socket_read_thread.join().unwrap()?;

    Ok(())
}
