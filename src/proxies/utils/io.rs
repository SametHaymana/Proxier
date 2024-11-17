use tokio::net::TcpListener;

pub async fn is_port_in_use(port: u16) -> bool {
    let address = format!("127.0.0.1:{}", port);
    match TcpListener::bind(&address).await {
        Ok(listener) => {
            drop(listener); // Release the listener
            false
        }
        Err(_) => true,
    }
}
