use libc::{__errno_location, EAGAIN, EINTR, POLLIN, poll, pollfd};
use std::{net::UdpSocket, os::fd::AsRawFd};

use crate::Error;
use crate::tun::Tun;

pub struct SocketPoller {
    pollfds: [pollfd; 2],
}

pub struct PollResult {
    /// The network interface has data to read.
    pub can_read_network: bool,
    /// The tun interface has data to read.
    pub can_read_tun: bool,
}

impl SocketPoller {
    pub fn new(physical_interface: &UdpSocket, tun_interface: &Tun) -> Self {
        let net_pollfd = pollfd {
            fd: physical_interface.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let tun_pollfd = pollfd {
            fd: tun_interface.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        SocketPoller {
            pollfds: [net_pollfd, tun_pollfd],
        }
    }

    /// This method returns when the network and/or tun interface have more data to read.
    /// Depending on the settings of [`set_want_write_network`] and [`set_want_write_tun`], it can
    /// also return when the interfaces are ready for writing.
    pub fn poll(&mut self, timeout: i32, retry: bool) -> Result<PollResult, Error> {
        loop {
            let poll_rv = unsafe {
                *__errno_location() = 0;
                poll(
                    (&mut self.pollfds).as_mut_ptr(),
                    self.pollfds.len() as u64,
                    timeout,
                )
            };
            if poll_rv >= 0 {
                return Ok(PollResult {
                    can_read_network: self.pollfds[0].revents & POLLIN != 0,
                    can_read_tun: self.pollfds[1].revents & POLLIN != 0,
                });
            } else {
                let errno = unsafe { *__errno_location() };
                if errno == EAGAIN || errno == EINTR {
                    if !retry {
                        return Err(Error::retry("poll was interrupted"));
                    }
                } else {
                    return Err(Error::Unknown(format!("poll error: {}", errno)));
                }
            }
        }
    }
}
