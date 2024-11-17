mod models;
mod proxies;

use dotenv::dotenv;
use proxies::proxy_manager::{ProxyManager, ProxyType};
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

    let mut proxy = ProxyManager::new();

    let sockProxy = proxy
        .add_proxy(ProxyType::Socks5, 1080)
        .await
        .unwrap();


        
    let sockProxy2 = proxy
        .add_proxy(ProxyType::Socks5, 1111)
        .await
        .unwrap();

    loop {
        
    }

    info!("Application Starting");
}
