extern crate openssl;
extern crate rand;

mod control_channel;
mod packets;
mod retransmit;

use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream};
use std::env;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
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
    let args = std::vec::Vec::from_iter(env::args());
    if args.len() < 3 {
        return Result::Err(Box::new(E {}));
    }
    let socket = UdpSocket::bind(("127.0.0.1", 50000))?;
    socket.set_nonblocking(true)?;
    let port = u16::from_str_radix(&args[2], 10)?;
    socket.connect((&args[1][..], port))?;
    println!("Connected to {}:{}", &args[1][..], port);

    let mut control_channel = ControlChannel::new(&mut rand::rng(), socket.try_clone()?);
    let mut receive_buffer: [u8; 1024] = [0; 1024];

    control_channel.client_reset()?;

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    socket.set_nonblocking(false)?;
    let mut stream = connector.connect("OpenVPN", &mut control_channel).unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{:?}", res);
    Ok(())
}
