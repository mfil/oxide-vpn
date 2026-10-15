extern crate bitflags;
extern crate clap;
extern crate libc;
extern crate memsec;
extern crate openssl;
extern crate rand;

use std::fs::File;
use std::io::{Read, Write};
use std::mem::min_align_of_val;
use std::net::UdpSocket;
use std::time::Instant;

use clap::Parser;
use libc::{IFLA_INFO_XSTATS, NETLINK_FIB_LOOKUP};
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::rng;

mod control_channel;
mod data_channel;
mod error;
mod packets;
mod poll;
mod tun;

use control_channel::ControlChannel;
use control_channel::messages::{IvProto, PeerInfo, PushReply};
use data_channel::{AES_256_GCM, DataChannel};
use error::{Error, catch_would_block};
use packets::{Packet, PacketBuffer};

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

    let mut control_channel = ControlChannel::new(
        &mut rng(),
        false,
        X509::from_pem(&ca_pem)?,
        X509::from_pem(&cert_pem)?,
        PKey::private_key_from_pem(&key_pem)?,
        args.peer_name,
    );
    let mut data_channel: Option<DataChannel> = None;

    let mut poller = poll::SocketPoller::new(&socket, &tun);
    let mut state = ConnectionState::Uninitialized;

    let mut packet_buffer = PacketBuffer::new(3000);
    let mut read_buffer = [0u8; 3000];
    let mut write_buffer = [0u8; 3000];

    control_channel.reset();
    socket.set_nonblocking(true)?;
    control_channel.send(Instant::now(), &mut |data| socket.send(data))?;

    loop {
        let poll_result = poller.poll(-1, true)?;

        if poll_result.can_read_network {
            match packet_buffer.recv_packet(&socket) {
                Ok(Packet::Control(p)) => control_channel.receive_packet(p)?,
                Ok(Packet::Data(p)) => {
                    if let Some(data_channel) = &mut data_channel {
                        let decrypted_packet = data_channel.decrypt_packet(p)?;
                        if let Err(e) = tun.write(&decrypted_packet) {
                            catch_would_block(e)?;
                        }
                    } else {
                        println!("Received data channel packet before it is ready, ignoring.");
                    }
                }
                Err(e) => catch_would_block(e)?,
            }
        }

        if poll_result.can_read_tun
            && let Some(data_channel) = &mut data_channel
        {
            match packet_buffer.read_data_channel_plaintext(&mut tun) {
                Ok(mut data_packet_buffer) => {
                    data_channel.encrypt_packet(&mut data_packet_buffer)?;
                    if let Err(e) = socket.send(data_packet_buffer.as_slice()) {
                        catch_would_block(e)?;
                    }
                }
                Err(e) => {
                    // It is possible that we get a WouldBlock error, even though poll told us that
                    // we can read. So check if this is an actual error before returning it.
                    catch_would_block(e)?;
                }
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
                    let push_reply =
                        PushReply::parse(str::from_utf8(&read_buffer[..length - 1]).unwrap())?;
                    if !push_reply.protocol_flags.aead_epoch {
                        println!("Peer does not support aead-epoch.");
                        break;
                    }
                    if let Ok(keys) = control_channel.derive_data_channel_keys() {
                        data_channel = Some(DataChannel::new(
                            push_reply.peer_id,
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
        let send_result = control_channel.send(Instant::now(), &mut |data| socket.send(data));
        if let Err(e) = send_result {
            catch_would_block(e)?;
        }
    }
    Ok(())
}
