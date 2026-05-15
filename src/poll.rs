use libc::{__errno_location, EAGAIN, EINTR, POLLIN, c_int, poll, pollfd};
use std::{net::UdpSocket, os::fd::AsRawFd};

pub struct SocketPoller {
    phys_pollfd: pollfd,
}

impl SocketPoller {
    pub fn new(physical_interface: &UdpSocket) -> Self {
        SocketPoller {
            phys_pollfd: pollfd {
                fd: physical_interface.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            },
        }
    }

    pub fn wait_for_data(&mut self, timeout: i32, retry: bool) -> Result<(), c_int> {
        loop {
            let poll_rv = unsafe {
                *__errno_location() = 0;
                poll(&mut self.phys_pollfd, 1, timeout)
            };
            if poll_rv >= 0 {
                return Ok(());
            } else {
                let errno = unsafe { *__errno_location() };
                if !retry || (errno != EAGAIN && errno != EINTR) {
                    return Err(errno);
                }
            }
        }
    }

    pub fn can_read_phys(&self) -> bool {
        self.phys_pollfd.revents & POLLIN != 0
    }
}
