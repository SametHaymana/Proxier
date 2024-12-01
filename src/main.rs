mod models;
mod proxies;

use std::time::{self, Duration};

use dotenv::dotenv;
use metrics_exporter_prometheus::PrometheusBuilder;
use models::users::User;
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

    info!("Application Starting");

    let mut proxy_manager = ProxyManager::new();

    let proxy_id = proxy_manager
        .add_proxy(ProxyType::Socks5, 1080)
        .await
        .unwrap();


    proxy_manager.list_auth_methods(&proxy_id).await;

    // Set access as non passoword
    proxy_manager.set_auth_method(&proxy_id, 0).await;

    // Also with password
    proxy_manager.set_auth_method(&proxy_id, 2).await;

    let user = User::new("samet", "password");

    // register to user
    proxy_manager
        .register_user(Some(&proxy_id), user)
        .await;



    let one_mb = 1024*1024;

    proxy_manager.set_max_bandwith(&proxy_id, one_mb).await;

    loop {}
}
