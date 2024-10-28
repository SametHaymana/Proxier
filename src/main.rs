mod models;
mod proxies;

use dotenv::dotenv;
use proxies::socks5::Socks5Proxy;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .init();

    info!("Application Starting");

    let proxy = Socks5Proxy::new(1080);

    proxy.start().await;
}

/*
use crate::proxy::Proxy;
use crate::socks5::libs::statics::AuthMethods;
use socks5::{handlers, libs::statics::FromToU8};
use std::{io, sync::{Arc}};
use tokio;



#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let server_port: i32 = 1080;

    let mut proxy: Proxy = proxy::Proxy::new();

    proxy.add_method(AuthMethods::NoAuth.to_u8());
    proxy.add_method(AuthMethods::UsernamePassword.to_u8());


    // Create defoult user and password
    proxy.add_user(
        String::from("user"),
        String::from("pass"),
    );

    let proxy_arc = Arc::new(proxy);

    tokio::spawn(async move {
        // Create a new Tokio runtime
        match handlers::start_proxy(
            proxy_arc,
            Some(server_port.clone()),
        )
        .await
        {
            socks5::libs::errors::ProxyResult::Err(_e) => {}
            socks5::libs::errors::ProxyResult::Ok(_n) => {}
        }
    });

    loop {/* Loop for serving */ }

    Ok(())
}

*/
