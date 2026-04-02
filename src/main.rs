extern crate openssl;
extern crate rand;

mod control_channel;
mod packets;
mod retransmit;

use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode, SslVersion};
use std::env;
use std::error::Error;
use std::fmt;
use std::net::UdpSocket;

use control_channel::ControlChannel;

#[derive(Debug)]
struct E {}

impl fmt::Display for E {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl Error for E {}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");
    /*
    let args = std::vec::Vec::from_iter(env::args());
    if args.len() < 6 {
        return Result::Err(Box::new(E {}));
    }
    let socket = UdpSocket::bind(("127.0.0.1", 50000))?;
    socket.set_nonblocking(true)?;
    let address = &args[1][..];
    let port = u16::from_str_radix(&args[2], 10)?;
    let ca_path = &args[3];
    let cert_path = &args[4];
    let key_path = &args[5];
    socket.connect((address, port))?;
    println!("Connected to {}:{}", &args[1][..], port);

    let mut control_channel = ControlChannel::new(&mut rand::rng(), socket.try_clone()?);
    control_channel.client_reset()?;
    let mut stream = TlsRecordStream::new(&mut control_channel);

    let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    connector_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    connector_builder.set_ca_file(ca_path)?;
    connector_builder.set_certificate_file(cert_path, SslFiletype::PEM)?;
    connector_builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    let mode = SslVerifyMode::NONE;
    connector_builder.set_verify(mode);
    let connector = connector_builder.build();
    socket.set_nonblocking(false)?;
    loop {
        if let Err(e) = connector.connect("OpenVPN", &mut stream) {
            match e {
                WouldBlock => std::thread::sleep(std::time::Duration::from_secs(10)),
                _ => panic!("at the disco"),
            }
        } else {
            break;
        }
    }
    //let mut res = vec![];
    //stream.read_to_end(&mut res).unwrap();
    //println!("{:?}", res);
    */
    Ok(())
}
