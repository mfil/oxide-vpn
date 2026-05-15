extern crate bitflags;
extern crate libc;
extern crate memsec;
extern crate openssl;
extern crate rand;

use std::env;
use std::error::Error;
use std::fmt::{self, Debug};
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
mod data_channel;
mod packets;
mod poll;
mod retransmit;

use control_channel::ControlChannel;
use control_channel::messages::{IvProto, PeerInfo};
use data_channel::{AES_256_GCM, DataChannel};
use packets::{ControlChannelPacket, DataChannelPacket, Packet, PacketError};

#[derive(Debug)]
struct E {}

impl fmt::Display for E {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl Error for E {}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn receive_packet(socket: &UdpSocket) -> Result<Packet, PacketError> {
    let mut read_buffer: [u8; 3000] = [0; 3000];
    let length = socket.recv(&mut read_buffer).unwrap();
    Packet::parse(&read_buffer[..length])
}

fn print_packet(data: &[u8]) {
    println!("\nDecrypted IP packet");
    if data.len() < 20 {
        println!("Packet too small");
        return;
    }

    if data[0] >> 4 != 4 {
        println!("Not an IPv4 packet");
        return;
    }
    let header_length = (data[0] & 0x0f) as usize * size_of::<u32>();
    println!("IP header length = {}", header_length);
    let (_, rest) = data.split_at(2);
    let (total_length_bytes, rest) = rest.split_first_chunk::<2>().unwrap();
    let total_length = u16::from_be_bytes(*total_length_bytes) as usize;
    if total_length < header_length {
        println!("Invalid packet length");
        return;
    }
    println!("Total packet length = {}", total_length);

    let (_, rest) = rest.split_at(5);
    let (protocol_byte, rest) = rest.split_first().unwrap();
    match protocol_byte {
        1 => println!("ICMP packet"),
        2 => println!("IGMP packet"),
        6 => println!("TCP packet"),
        17 => println!("UDP packet"),
        _ => println!("Other packet"),
    };

    let (_, rest) = rest.split_at(2);
    let (source_addr_bytes, rest) = rest.split_first_chunk::<4>().unwrap();
    println!(
        "Source address = {}.{}.{}.{}",
        source_addr_bytes[0], source_addr_bytes[1], source_addr_bytes[2], source_addr_bytes[3]
    );
    let (dest_addr_bytes, rest) = rest.split_first_chunk::<4>().unwrap();
    println!(
        "Destination address = {}.{}.{}.{}",
        dest_addr_bytes[0], dest_addr_bytes[1], dest_addr_bytes[2], dest_addr_bytes[3]
    );

    let (_, payload) = rest.split_at(header_length - 20);
    if *protocol_byte == 17 {
        let (source_port_bytes, rest) = payload.split_first_chunk::<2>().unwrap();
        println!("Source port: {}", u16::from_be_bytes(*source_port_bytes));
        let (dest_port_bytes, rest) = rest.split_first_chunk::<2>().unwrap();
        println!("Dest port: {}", u16::from_be_bytes(*dest_port_bytes));

        let (_, rest) = rest.split_at(4);
        println!("Valid UTF8 chunks from the packet body:");
        for chunk in rest.utf8_chunks() {
            println!("{}", chunk.valid());
            if chunk.invalid().len() > 0 {
                println!("{} non-UTF8 bytes", chunk.invalid().len());
            }
        }
    }
}

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

    let (control_send, outgoing_receive) = channel();

    let mut control_channel = ControlChannel::new(
        &mut rng(),
        false,
        X509::from_pem(&ca_pem)?,
        X509::from_pem(&cert_pem)?,
        PKey::private_key_from_pem(&key_pem)?,
        "Oxide VPN Test Server",
        |packet| control_send.send(packet).unwrap(),
    );

    let mut poller = poll::SocketPoller::new(&socket);

    let socket_write = socket.try_clone()?;
    let socket_write_thread = thread::spawn(move || -> std::io::Result<()> {
        let socket = socket_write;
        let mut write_buffer: [u8; 3000] = [0; 3000];
        let receive_channel = outgoing_receive;
        while !SHUTDOWN.load(Ordering::Relaxed) {
            let packet = receive_channel.recv().unwrap();
            if packet.opcode != crate::packets::Opcode::ControlHardResetClientV2
                && packet.peer_session_id.is_none()
            {
                println!("oh no");
            }
            let length = packet.to_buffer(&mut write_buffer).unwrap();
            socket.send(&write_buffer[..length])?;
        }
        Ok(())
    });

    let mut read_buffer: [u8; 3000] = [0; 3000];
    control_channel.reset();
    while !control_channel.is_connected() {
        poller.wait_for_data(-1, true).unwrap();
        if poller.can_read_phys() {
            let packet = receive_packet(&socket)?;
            if let Packet::Control(p) = packet {
                control_channel.receive_packet(p);
            }
        }
    }
    let peer_info = PeerInfo {
        iv_proto: IvProto::SUPPORT_DATA_V2
            | IvProto::EXPECT_PUSH_REPLY
            | IvProto::CAN_DO_KEY_MAT_EXPORT
            | IvProto::EPOCH_DATA_FORMAT,
        iv_ciphers: "AES-256-GCM:CHACHA20-POLY1305",
    };
    let mut write_buffer: [u8; 2000] = [0; 2000];
    let length = peer_info.to_buffer(&mut rng(), &mut write_buffer);
    control_channel.write(&write_buffer[..length])?;
    control_channel.flush()?;
    let mut got_key_exchange = false;
    let mut got_push_reply = false;
    while !SHUTDOWN.load(Ordering::Relaxed) {
        while !got_key_exchange {
            poller.wait_for_data(-1, true).unwrap();
            if poller.can_read_phys() {
                let packet = receive_packet(&socket)?;
                if let Packet::Control(p) = packet {
                    control_channel.receive_packet(p);
                }
            }
            if let Ok(length) = control_channel.read(&mut read_buffer) {
                if length > 5 && read_buffer[..5] == [0, 0, 0, 0, 2] {
                    got_key_exchange = true;
                }
            }
        }
        control_channel.write(b"PUSH_REQUEST")?;
        control_channel.flush()?;
        while !got_push_reply {
            poller.wait_for_data(0, true).unwrap();
            if poller.can_read_phys() {
                let packet = receive_packet(&socket)?;
                if let Packet::Control(p) = packet {
                    control_channel.receive_packet(p);
                }
            } else {
                thread::sleep(std::time::Duration::from_secs(1));
            }
            if let Ok(length) = control_channel.read(&mut read_buffer) {
                let reply_str = b"PUSH_REPLY";
                if length >= reply_str.len() && read_buffer[..reply_str.len()] == reply_str[..] {
                    got_push_reply = true;
                    println!("{}", str::from_utf8(&read_buffer[..length]).unwrap());
                }
            }
        }
        let data_channel_keys = control_channel.derive_data_channel_keys().unwrap();
        let mut data_channel = DataChannel::new(
            [0, 0, 0],
            AES_256_GCM,
            data_channel_keys.client_to_server,
            data_channel_keys.server_to_client,
        );
        loop {
            poller.wait_for_data(-1, true).unwrap();
            if poller.can_read_phys() {
                let packet = receive_packet(&socket)?;
                if let Packet::Data(p) = packet {
                    let decrypted = data_channel.decrypt_packet(p).unwrap();
                    print_packet(&decrypted);
                }
            }
        }
    }

    socket_write_thread.join().unwrap()?;

    Ok(())
}
