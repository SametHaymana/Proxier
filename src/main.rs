#![allow(dead_code)]

mod proxy;
mod socks5;

use crate::proxy::Proxy;
use crate::socks5::libs::statics::AuthMethods;
use socks5::handlers;
use std::{error::Error, sync::Arc};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_addr: String = String::from("0.0.0.0");
    let server_port: i32 = 1080;

    tokio::spawn(async move {
        // new vec of auth methods
        let mut auth_types: Vec<AuthMethods> = Vec::new();

        // add auth methods
        auth_types.push(AuthMethods::NoAuth);
        auth_types.push(AuthMethods::UsernamePassword);

        let mut proxy: Proxy =
            proxy::Proxy::new(auth_types);

        // Create defoult user and password
        proxy.add_user(
            String::from("user"),
            String::from("pass"),
        );

        // Create a new Tokio runtime
        match handlers::start_proxy(
            Arc::new(proxy),
            Some(server_addr.clone()),
            Some(server_port.clone()),
        )
        .await
        {
            socks5::libs::errors::ProxyResult::Err(_e) => {}
            socks5::libs::errors::ProxyResult::Ok(_n) => {
                println!(
                    "Server started on {}:{}",
                    server_addr, server_port
                );
            }
        }
    });

    // Lock
    loop {}
}
