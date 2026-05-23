extern crate bitflags;
extern crate clap;
extern crate libc;
extern crate memsec;
extern crate openssl;
extern crate rand;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread;

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

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

    /// Name of the tun interface to use.
    #[arg(long, default_value = "")]
    tun: String,
}

fn receive_packet(socket: &UdpSocket) -> Result<Packet, Error> {
    let mut read_buffer: [u8; 3000] = [0; 3000];
    let length = socket.recv(&mut read_buffer).unwrap();
    Packet::parse(&read_buffer[..length])
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

    let mut poller = poll::SocketPoller::new(&socket, &tun);

    let socket_write = socket.try_clone()?;
    let socket_write_thread = thread::spawn(move || -> std::io::Result<()> {
        let socket = socket_write;
        let mut write_buffer: [u8; 3000] = [0; 3000];
        let receive_channel = outgoing_receive;
        while !SHUTDOWN.load(Ordering::Relaxed) {
            if let Ok(packet) = receive_channel.recv() {
                if packet.opcode != crate::packets::Opcode::ControlHardResetClientV2
                    && packet.peer_session_id.is_none()
                {
                    println!("oh no");
                }
                let length = packet.to_buffer(&mut write_buffer).unwrap();
                socket.send(&write_buffer[..length])?;
            }
        }
        Ok(())
    });

    let mut read_buffer: [u8; 3000] = [0; 3000];
    control_channel.reset();
    while !control_channel.is_connected() {
        let poll_result = poller.poll(-1, true).unwrap();
        if poll_result.can_read_network {
            let packet = receive_packet(&socket)?;
            if let Packet::Control(p) = packet {
                control_channel.receive_packet(p)?;
            }
        }
    }
    let peer_info = PeerInfo {
        iv_proto: IvProto::SUPPORT_DATA_V2
            | IvProto::EXPECT_PUSH_REPLY
            | IvProto::CAN_DO_KEY_MAT_EXPORT
            | IvProto::EPOCH_DATA_FORMAT,
        iv_ciphers: "AES-256-GCM",
    };
    let mut write_buffer: [u8; 2000] = [0; 2000];
    let length = peer_info.to_buffer(&mut rng(), &mut write_buffer);
    control_channel.write(&write_buffer[..length])?;
    control_channel.flush()?;
    let mut got_key_exchange = false;
    let mut got_push_reply = false;
    while !SHUTDOWN.load(Ordering::Relaxed) {
        while !got_key_exchange {
            let poll_result = poller.poll(-1, true).unwrap();
            if poll_result.can_read_network {
                let packet = receive_packet(&socket)?;
                if let Packet::Control(p) = packet {
                    control_channel.receive_packet(p)?;
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
            let poll_result = poller.poll(-1, true).unwrap();
            if poll_result.can_read_network {
                let packet = receive_packet(&socket)?;
                if let Packet::Control(p) = packet {
                    control_channel.receive_packet(p)?;
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
            let poll_result = poller.poll(-1, true).unwrap();
            if poll_result.can_read_network {
                let packet = receive_packet(&socket)?;
                if let Packet::Data(p) = packet {
                    let decrypted = data_channel.decrypt_packet(p).unwrap();
                    tun.write(&decrypted)?;
                }
            }
        }
    }

    socket_write_thread.join().unwrap()?;

    Ok(())
}
