use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

use std::{
    collections::{BTreeMap, HashSet}, io, net::IpAddr, sync::Arc,
};

use crate::models::users::{User, UserId};

use super::{
    http::HttpProxy, socks5::Socks5Proxy,
    utils::io::is_port_in_use,
};

use tracing::error;

pub enum ProxyType {
    Http,
    Socks5,
}

#[async_trait]
pub trait ProxyEx:   Send + Sync {
    // Start proxy
    async fn start(&self) -> Result<(), String>;

    async fn set_avaliable_auth_methods(
        &mut self,
        methods: Vec<u8>,
    );
    async fn avaliable_auth_methods(&self) -> Vec<u8>;

    async fn avaliable_users(
        &self,
    ) -> Arc<RwLock<HashSet<Arc<User>>>>;
    async fn set_user(&mut self, user: Arc<User>);
    async fn remove_user(&mut self, user_id: &str) -> bool;

    // Analistic
}

pub struct ProxyManager {
    users: Arc<RwLock<HashSet<User>>>,
    // (Proxy, port)
    avaliable_proxies:
        Arc<RwLock<BTreeMap<String,(Arc<Box<dyn ProxyEx>>, u16)>>>,

    // Blocked Domain or ipAddrs
    blocked_ippaddr: Arc<RwLock<HashSet<IpAddr>>>,

    // Analistic
    total_bytes_served: u128,
}

impl ProxyManager {
    pub fn new() -> Self {
        ProxyManager {
            users: Arc::new(RwLock::new(HashSet::new())),
            avaliable_proxies: Arc::new(RwLock::new(
                BTreeMap::new(),
            )),
            blocked_ippaddr: Arc::new(RwLock::new(
                HashSet::new(),
            )),
            total_bytes_served: 0,
        }
    }

    pub async fn add_proxy(
        &mut self,
        proxy_type: ProxyType,
        port: u16,
    ) -> Result<(Arc<Box<dyn ProxyEx>>, u16), String> {
        if is_port_in_use(port).await {
            return Err("Port in use!".to_string());
        }
    
        let proxy: Box<dyn ProxyEx> = match proxy_type {
            ProxyType::Socks5 => Box::new(Socks5Proxy::new(port)),
            ProxyType::Http => Box::new(HttpProxy::new()),
            _ => return Err("Proxy impl not available".to_string()),
        };
    
        let proxy_arc = Arc::new(proxy);
    
        let proxy_clone = Arc::clone(&proxy_arc);
    
        tokio::spawn(async move {
            if let Err(e) = proxy_clone.start().await {
                error!("Error starting proxy on port {}: {}", port, e);
            }
        });


        // Store in Vec
        let mut avaliable_proxies = self.avaliable_proxies.write();
        let id = Self::create_proxy_id();
        avaliable_proxies.insert(id,(proxy_arc.clone(), port));
        
    
        // Return the Arc to the caller along with the port number
        Ok((proxy_arc, port))
    }



    fn create_proxy_id() -> String{
        Uuid::new_v4().to_string()
    }

}
