use std::fmt;
use tokio::io;

#[derive(Debug)]
pub enum ProxyError {
    IoError(io::Error),
    ParseError(String),
    ConnectionError(String),
    TimeoutError(String),
}

impl fmt::Display for ProxyError {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            ProxyError::IoError(err) => {
                write!(f, "I/O Error: {}", err)
            }
            ProxyError::ParseError(msg) => {
                write!(f, "Parse Error: {}", msg)
            }
            ProxyError::ConnectionError(msg) => {
                write!(f, "Connection Error: {}", msg)
            }
            ProxyError::TimeoutError(msg) => {
                write!(f, "Timeout Error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
