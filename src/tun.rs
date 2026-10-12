use libc::{
    __c_anonymous_ifr_ifru, __errno_location, EINTR, EPERM, IFF_NO_PI, IFF_TUN, IFNAMSIZ,
    O_NONBLOCK, O_RDWR, TUNSETIFF, c_char, c_void, close, ifreq, ioctl, open, read, ssize_t,
    strlen, write,
};

use std::io;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::*;
use std::ptr::copy_nonoverlapping;

use crate::error::Error;

/// Closes `fd`, and keeps retrying if there was a retry-able error.
unsafe fn close_fd(fd: RawFd) {
    unsafe {
        loop {
            if close(fd) == 0 {
                return;
            }
            let errno = *__errno_location();
            if errno != EINTR {
                // If threre's an error other than EINTR, there's nothing we can really do about it.
                return;
            }
        }
    }
}

/// The tun interface.
///
/// The virtual network interface where the plain-text packets are sent and received.
pub struct Tun {
    name: Vec<u8>,
    fd: RawFd,
}

impl Tun {
    /// Create or open a tun interface specified by `name`.
    ///
    /// If `name` is an empty slice, a new tun interface will be created with a new automatically
    /// assigned name (tunX).
    pub fn open(name: &[u8]) -> Result<Self, Error> {
        if name.len() >= IFNAMSIZ {
            return Err(Error::argument_error(format!(
                "Tun device names can be at most {} bytes",
                IFNAMSIZ - 1
            )));
        }

        unsafe {
            // Open /dev/net/tun as a raw file descriptor, because Rust's Files are always blocking.
            let path = "/dev/net/tun\0".as_ptr() as *const c_char;
            let fd = open(path, O_RDWR | O_NONBLOCK);
            if fd < 0 {
                let errno = *__errno_location();
                let io_error = io::Error::from_raw_os_error(errno);
                return Err(Error::from(io_error));
            }

            // Set the name and options of the tun interface.
            let mut req = ifreq {
                ifr_name: [0; IFNAMSIZ],
                ifr_ifru: __c_anonymous_ifr_ifru {
                    ifru_flags: (IFF_TUN | IFF_NO_PI) as i16,
                },
            };
            copy_nonoverlapping(
                name.as_ptr() as *const i8,
                req.ifr_name.as_mut_ptr(),
                name.len(),
            );
            req.ifr_ifru = __c_anonymous_ifr_ifru {
                ifru_flags: (IFF_TUN | IFF_NO_PI) as i16,
            };
            let req_ptr = ((&mut req) as *mut ifreq) as *mut c_char;
            if ioctl(fd, TUNSETIFF, req_ptr) < 0 {
                // We failed to create or open the tun interface, so now we need to close the fd
                // and then return the error. First, we need to save the errno from ioctl, because
                // calling close can overwrite it.
                let errno = *__errno_location();
                close_fd(fd);
                // TODO: Check if there are more error codes that might be expected here.
                match errno {
                    EPERM => {
                        return Err(Error::permission_error(
                            "User is not allowed to create/open the tun interface.",
                        ));
                    }
                    _ => return Err(Error::Unknown(format!("ioctl returned {}", errno))),
                }
            }

            let name_ptr = req.ifr_name.as_slice().as_ptr();
            let name_len = strlen(name_ptr);
            let mut assigned_name = vec![0; name_len];
            copy_nonoverlapping(name_ptr as *mut u8, assigned_name.as_mut_ptr(), name_len);

            Ok(Tun {
                name: assigned_name,
                fd,
            })
        }
    }
}

impl Read for Tun {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let buffer_pointer = buffer.as_mut_ptr() as *mut c_void;
        unsafe {
            let bytes_read: ssize_t = read(self.fd, buffer_pointer, buffer.len());
            if bytes_read < 0 {
                let errno = *__errno_location();
                Err(io::Error::from_raw_os_error(errno))
            } else {
                Ok(bytes_read as usize)
            }
        }
    }
}

impl Write for Tun {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let buffer_pointer = buffer.as_ptr() as *const c_void;
        unsafe {
            let bytes_written: ssize_t = write(self.fd, buffer_pointer, buffer.len());
            if bytes_written < 0 {
                let errno = *__errno_location();
                Err(io::Error::from_raw_os_error(errno))
            } else {
                Ok(bytes_written as usize)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // No-op because we're not doing any buffering.
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
