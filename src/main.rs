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

