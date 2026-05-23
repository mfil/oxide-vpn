use std::convert::From;
use std::error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    MalformedPacket(String),
    InvalidArgument(String),
    PermissionDenied(String),
    Handshake(String),
    Retry(String),
    Io(io::Error),
    Ssl(openssl::error::ErrorStack),
    Unknown(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::MalformedPacket(s) => write!(formatter, "Received bad OpenVPN packet: {}", s),
            Error::InvalidArgument(s) => write!(formatter, "Invalid argument: {}", s),
            Error::PermissionDenied(s) => write!(formatter, "Permission denied: {}", s),
            Error::Handshake(s) => write!(formatter, "Handshake failed: {}", s),
            Error::Retry(s) => write!(formatter, "Temporary error: {}", s),
            Error::Io(e) => write!(formatter, "IO Error: {}", e),
            Error::Ssl(e) => write!(formatter, "OpenSSL Error: {}", e),
            Error::Unknown(s) => write!(formatter, "Unknown error: {}", s),
        }
    }
}

impl Error {
    pub fn packet_error<S: Into<String>>(message: S) -> Self {
        Error::MalformedPacket(message.into())
    }

    pub fn argument_error<S: Into<String>>(message: S) -> Self {
        Error::InvalidArgument(message.into())
    }

    pub fn permission_error<S: Into<String>>(message: S) -> Self {
        Error::PermissionDenied(message.into())
    }

    pub fn retry<S: Into<String>>(message: S) -> Self {
        Error::Retry(message.into())
    }
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        Error::Ssl(error)
    }
}

impl<T: fmt::Debug> From<openssl::ssl::HandshakeError<T>> for Error {
    fn from(error: openssl::ssl::HandshakeError<T>) -> Self {
        Error::Handshake(format!("{}", error))
    }
}
