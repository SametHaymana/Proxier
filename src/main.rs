#![allow(dead_code)]

mod socks5;

use std::{error::Error, sync::Arc};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_addr: String = String::from("0.0.0.0");
    let server_port: i32 = 1080;

    tokio::spawn(async move {
        // new vec of auth methods
        let mut authTypes: Vec<socks5::AuthMethods> = Vec::new();

        // add auth methods
        authTypes.push(socks5::AuthMethods::NoAuth);
        authTypes.push(socks5::AuthMethods::UsernamePassword);

        let mut proxy: socks5::Proxy = socks5::Proxy::new(authTypes);

        // Create defoult user and password
        proxy.add_user(String::from("user"), String::from("pass"));

        // Create a new Tokio runtime
        match socks5::start_proxy(
            Arc::new(proxy),
            Some(server_addr),
            Some(server_port),
        )
        .await
        {
            Ok(_) => {
                println!("Proxy thread finished");
            }
            Err(e) => {
                println!("Error in proxy thread: {}", e);
            }
        }
    });

    // Lock
    while true {}

    Ok(())
}
