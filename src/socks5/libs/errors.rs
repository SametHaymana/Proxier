#[derive(Debug)]
pub enum ProxyError {
    LocalPortBindError,
    IoReadingError,
    AuthError,
    ReplyError,
    RemoteConnectionError,
    ServerError,
}

pub enum ProxyResult<T> {
    Ok(T),
    Err(ProxyError),
}

impl<T> ProxyResult<T> {
    fn is_ok(&self) -> bool {
        matches!(*self, ProxyResult::Ok(_))
    }

    fn unwrap(self) -> T {
        match self {
            ProxyResult::Ok(val) => val,
            ProxyResult::Err(_e) => {
                panic!("Proxy panic err: {:?}", _e)
            }
        }
    }
}
