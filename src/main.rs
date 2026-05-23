extern crate bitflags;
extern crate clap;
extern crate libc;
extern crate memsec;
extern crate openssl;
extern crate rand;

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::{env, io};

use clap::Parser;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::rng;

mod control_channel;
mod data_channel;
mod error;
mod packets;
mod poll;
mod retransmit;
mod tun;

use control_channel::ControlChannel;
use control_channel::messages::{IvProto, PeerInfo};
use data_channel::{AES_256_GCM, DataChannel};
use error::Error;
use packets::Packet;

#[derive(Parser)]
#[clap(name = "OxideVPN", version = "0.1.0", author = "Max Fillinger")]
/// OpenVPN client implementation in Rust with obligatory rust pun.
struct Args {
    /// IP address of the OpenVPN server.
    #[arg(short, long)]
    remote: String,

    /// Port of the OpenVPN server.
    #[arg(short, long, default_value = "1194")]
    port: u16,

    /// Path to a CA certificate to validate the peer's certificate.
    #[arg(long)]
    ca: String,

    /// Path to the client's certificate.
    #[arg(long)]
    cert: String,

    /// Path to the client's private key.
    #[arg(long)]
    key: String,

    /// Common name of the server's certificate.
    #[arg(long, default_value = "Oxide VPN Test Server")]
    peer_name: String,

    /// Name of the tun interface to use.
    #[arg(long, default_value = "")]
    tun: String,
}

fn receive_packet(socket: &UdpSocket) -> Result<Packet, Error> {
    let mut read_buffer: [u8; 3000] = [0; 3000];
    let length = socket.recv(&mut read_buffer).unwrap();
    Packet::parse(&read_buffer[..length])
}

#[derive(PartialEq, Eq)]
enum ConnectionState {
    Uninitialized,
    HandshakeDone,
    ReceivedKeyExchange,
    ReceivedOptions,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut ca_file = File::open(args.ca)?;
    let mut ca_pem = Vec::new();
    let _ = ca_file.read_to_end(&mut ca_pem);

    let mut cert_file = File::open(args.cert)?;
    let mut cert_pem = Vec::new();
    let _ = cert_file.read_to_end(&mut cert_pem);

    let mut key_file = File::open(args.key)?;
    let mut key_pem = Vec::new();
    let _ = key_file.read_to_end(&mut key_pem);

    let mut tun = tun::Tun::open(args.tun.as_bytes())?;

    socket.connect((args.remote, args.port))?;

    let net_send_queue = RefCell::new(Vec::<Packet>::new());
    let mut control_channel = ControlChannel::new(
        &mut rng(),
        false,
        X509::from_pem(&ca_pem)?,
        X509::from_pem(&cert_pem)?,
        PKey::private_key_from_pem(&key_pem)?,
        args.peer_name,
        |packet| net_send_queue.borrow_mut().push(Packet::Control(packet)),
    );
    let mut data_channel: Option<DataChannel> = None;

    let mut poller = poll::SocketPoller::new(&socket, &tun);
    let mut state = ConnectionState::Uninitialized;

    let mut read_buffer: [u8; 3000] = [0; 3000];
    let mut write_buffer: [u8; 3000] = [0; 3000];

    control_channel.reset();
    control_channel.send_packets();
    let packet = net_send_queue.borrow_mut().pop().unwrap();
    let length = packet.to_buffer(&mut write_buffer)?;
    socket.send(&write_buffer[..length])?;
    socket.set_nonblocking(true)?;

    loop {
        let poll_result = poller.poll(-1, true)?;

        if poll_result.can_read_network {
            let packet = receive_packet(&socket)?;
            match packet {
                Packet::Control(p) => control_channel.receive_packet(p)?,
                Packet::Data(p) => {
                    if let Some(data_channel) = &mut data_channel {
                        let decrypted_packet = data_channel.decrypt_packet(p).unwrap();
                        tun.write(&decrypted_packet)?;
                    } else {
                        println!("Received data channel packet before it is ready, ignoring.");
                    }
                }
            }
        }

        if poll_result.can_read_tun {
            if let Some(data_channel) = &mut data_channel {
                let length = tun.read(&mut read_buffer)?;
                let encrypted_packet = data_channel.encrypt_packet(&read_buffer[..length])?;
                net_send_queue
                    .borrow_mut()
                    .push(Packet::Data(encrypted_packet));
            } else {
                println!(
                    "tun interface received packets before the data channel is ready, ignoring."
                );
            }
        }

        if state == ConnectionState::Uninitialized {
            if control_channel.is_connected() {
                state = ConnectionState::HandshakeDone;
                let peer_info = PeerInfo {
                    iv_proto: IvProto::SUPPORT_DATA_V2
                        | IvProto::EXPECT_PUSH_REPLY
                        | IvProto::CAN_DO_KEY_MAT_EXPORT
                        | IvProto::EPOCH_DATA_FORMAT,
                    iv_ciphers: "AES-256-GCM",
                };
                let length = peer_info.to_buffer(&mut rng(), &mut write_buffer);
                control_channel.write(&write_buffer[..length])?;
                control_channel.flush()?;
            }
        } else if state == ConnectionState::HandshakeDone {
            if let Ok(length) = control_channel.read(&mut read_buffer) {
                if length > 5 && read_buffer[..5] == [0, 0, 0, 0, 2] {
                    state = ConnectionState::ReceivedKeyExchange;
                    control_channel.write(b"PUSH_REQUEST")?;
                    control_channel.flush()?;
                }
            }
        } else if state == ConnectionState::ReceivedKeyExchange {
            if let Ok(length) = control_channel.read(&mut read_buffer) {
                let reply_str = b"PUSH_REPLY";
                if length >= reply_str.len() && read_buffer[..reply_str.len()] == reply_str[..] {
                    println!("{}", str::from_utf8(&read_buffer[..length]).unwrap());
                    if let Some(keys) = control_channel.derive_data_channel_keys() {
                        data_channel = Some(DataChannel::new(
                            [0, 0, 0],
                            AES_256_GCM,
                            keys.client_to_server,
                            keys.server_to_client,
                        ));
                        state = ConnectionState::ReceivedOptions;
                    }
                }
            }
        }

        // Try to send packets.
        control_channel.send_packets();
        let mut packets_sent = 0;
        let mut send_queue = net_send_queue.borrow_mut();
        for packet in send_queue.iter() {
            let length = packet.to_buffer(&mut write_buffer)?;
            let sent_bytes = match socket.send(&write_buffer[..length]) {
                Ok(length) => length,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    } else {
                        return Err(e)?;
                    }
                }
            };

            if sent_bytes < length {
                // Incomplete packet.
                break;
            }

            packets_sent += 1;
        }
        if packets_sent == send_queue.len() {
            send_queue.truncate(0);
            poller.set_want_write_network(false);
        } else {
            let new_send_queue = send_queue[packets_sent..].to_vec();
            *send_queue = new_send_queue;
        }
    }
}
