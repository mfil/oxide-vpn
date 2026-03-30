extern crate openssl;
extern crate rand;

use std::error::Error;

mod control_channel;
mod packets;
mod retransmit;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");
    Ok(())
}
