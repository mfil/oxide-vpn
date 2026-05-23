use libc::{
    __c_anonymous_ifr_ifru, __errno_location, EPERM, IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF,
    c_char, ifreq, ioctl, strlen,
};

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::ptr::copy_nonoverlapping;

use crate::error::Error;

/// The tun interface.
///
/// The virtual network interface where the plain-text packets are sent and received.
pub struct Tun {
    name: Vec<u8>,
    file: File,
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
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .open("/dev/net/tun")?;

        // Set the name and options of the tun interface.
        unsafe {
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
            if ioctl(file.as_raw_fd(), TUNSETIFF, req_ptr) < 0 {
                let errno = *__errno_location();
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
                file,
            })
        }
    }
}

impl Read for Tun {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for Tun {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.file.as_raw_fd()
    }
}
