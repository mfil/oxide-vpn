use libc::{__errno_location, EAGAIN, EINTR, POLLIN, POLLOUT, c_int, poll, pollfd};
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
    /// The network interface can be written to.
    ///
    /// Note that this will always be false unless the `SocketPoller` has been configured to poll
    /// for this event with `set_want_write_network`, but the interface can always be written to
    /// without blocking.
    pub can_write_network: bool,
    /// The tun interface can be written to.
    ///
    /// Note that this will always be false unless the `SocketPoller` has been configured to poll
    /// for this event with `set_want_write_tun`, but the interface can always be written to
    /// without blocking.
    pub can_write_tun: bool,
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
                    can_write_network: self.pollfds[0].revents & POLLOUT != 0,
                    can_write_tun: self.pollfds[1].revents & POLLOUT != 0,
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

    /// Tells the poller whether we want to return from [`poll`] if the network interface is ready
    /// for writing. It is always possible to write to the interface without blocking. This function
    /// is for when we couldn't write all the data we wanted to and we want to wake up from [`poll`]
    /// when we can write the rest.
    pub fn set_want_write_network(&mut self, want_write: bool) {
        self.pollfds[0].events = if want_write { POLLIN | POLLOUT } else { POLLIN };
    }

    /// Tells the poller whether we want to return from [`poll`] if the tun interface is ready for
    /// writing. It is always possible to write to the interface without blocking. This function is
    /// for when we couldn't write all the data we wanted to and we want to wake up from [`poll`]
    /// when we can write the rest.
    pub fn set_want_write_tun(&mut self, want_write: bool) {
        self.pollfds[1].events = if want_write { POLLIN | POLLOUT } else { POLLIN };
    }
}
