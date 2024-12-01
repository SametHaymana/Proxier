use async_trait::async_trait;
use dashmap::DashMap;
use tokio::sync::{oneshot, Mutex, RwLock};
use uuid::Uuid;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    io,
    net::IpAddr,
    sync::Arc,
};

use crate::models::users::{User, UserId};

use super::{
    http::HttpProxy, socks5::Socks5Proxy,
    utils::io::is_port_in_use,
};

use tracing::{error, info, warn};

pub enum ProxyType {
    Http,
    Socks5,
}

type StoredProxy = (Arc<Box<dyn ProxyEx>>, u16);

#[async_trait]
pub trait ProxyEx: Send + Sync + Debug {
    // Start proxy
    async fn start(&self) -> Result<(), String>;

    async fn avaliable_auth_methods(&self) -> HashSet<u8>;
    async fn set_avaliable_auth_method(
        &self,
        methods: Vec<u8>,
    );
    async fn remove_avaliable_auth_method(
        &self,
        methods: Vec<u8>,
    );

    async fn avaliable_users(&self) -> HashSet<User>;
    async fn set_user(&self, user: User);
    async fn remove_user(&self, user_id: &str) -> bool;

    async fn set_max_bandwith(&self, max: u64);

    // Analistic
}

#[derive(Debug)]
pub struct ProxyManager {
    users: Arc<RwLock<HashSet<User>>>,
    // (Proxy, port)
    //avaliable_proxies: Arc<RwLock<Vec<StoredProxy>>>,
    avaliable_proxies: Arc<DashMap<String, StoredProxy>>,

    // Blocked Domain or ipAddrs
    blocked_ippaddr: Arc<RwLock<HashSet<IpAddr>>>,

    // Analistic
    total_bytes_served: u128,
}

impl ProxyManager {
    pub fn new() -> Self {
        ProxyManager {
            users: Arc::new(RwLock::new(HashSet::new())),
            avaliable_proxies: Arc::new(DashMap::new()),

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
    ) -> Result<String, String> {
        if is_port_in_use(port).await {
            return Err("Port in use!".to_string());
        }

        // Create the proxy instance.
        let proxy: Box<dyn ProxyEx> = match proxy_type {
            ProxyType::Socks5 => {
                Box::new(Socks5Proxy::new(port))
            }
            //ProxyType::Http => Box::new(HttpProxy::new()),
            _ => {
                return Err(
                    "Proxy impl not available".to_string()
                )
            }
        };

        // Start proxy
        let _ = proxy.start().await;

        let id = Self::create_proxy_id();
        let proxy = Arc::new(proxy);
        self.avaliable_proxies
            .insert(id.clone(), (proxy, port));

        Ok(id)
    }

    pub fn get_proxy(
        &self,
        id: &String,
    ) -> Option<StoredProxy> {
        self.avaliable_proxies.get(id).map(|e| e.clone())
    }

    pub async fn list_auth_methods(
        &self,
        proxy_id: &String,
    ) -> Option<HashSet<u8>> {
        let stored_proxy = self.get_proxy(proxy_id)?;

        // Read the proxy and fetch its available authentication methods.
        let proxy = stored_proxy.0;
        let methods = proxy.avaliable_auth_methods().await;

        Some(methods)
    }

    pub async fn set_auth_method(
        &self,
        proxy_id: &String,
        method: u8,
    ) {
        // Get the proxy outside of any lock scope.
        let entry = match self.get_proxy(proxy_id) {
            Some(entry) => entry,
            None => {
                error!(
                    "Proxy not found for ID: {}",
                    proxy_id
                );
                return;
            }
        };

        let (proxy, _port) = entry;

        proxy.set_avaliable_auth_method(vec![method]).await;

        info!(
            "Added auth method {} for proxy ID: {}",
            method, proxy_id
        );
    }

    /// Remove an authentication method from a specific proxy
    pub async fn remove_auth_method(
        &self,
        proxy_id: &String,
        method: u8,
    ) {
        // Get the proxy outside of any lock scope.
        let entry = match self.get_proxy(proxy_id) {
            Some(entry) => entry,
            None => {
                error!(
                    "Proxy not found for ID: {}",
                    proxy_id
                );
                return;
            }
        };

        let (proxy, _) = entry;

        proxy
            .remove_avaliable_auth_method(vec![method])
            .await;
    }

    /// List users, either globally or for a specific proxy
    pub async fn list_users(
        &self,
        proxy_id: Option<&String>,
    ) -> Option<HashSet<User>> {
        match proxy_id {
            Some(id) => {
                let entry = match self.get_proxy(id) {
                    Some(entry) => entry,
                    None => {
                        error!(
                            "Proxy not found for ID: {}",
                            id
                        );
                        return None;
                    }
                };

                let (proxy, _port) = entry;

                let methods = proxy.avaliable_users().await;

                Some(methods)
            }
            None => {
                let users = self.users.read().await;

                Some(users.clone())
            }
        }
    }

    /// Register a user, either globally or for a specific proxy
    pub async fn register_user(
        &self,
        proxy_id: Option<&String>,
        user: User,
    ) {
        match proxy_id {
            Some(id) => {
                let entry = match self.get_proxy(id) {
                    Some(entry) => entry,
                    None => {
                        error!(
                            "Proxy not found for ID: {}",
                            id
                        );
                        return;
                    }
                };

                let (proxy, _) = entry;

                proxy.set_user(user).await;
            }
            None => {
                let mut users = self.users.write().await;
                users.insert(user);
            }
        }
    }

    /// Remove a user, either globally or for a specific proxy
    pub async fn remove_user(
        &self,
        proxy_id: Option<&String>,
        user: User,
    ) {
        match proxy_id {
            Some(id) => {
                let entry = match self.get_proxy(id) {
                    Some(entry) => entry,
                    None => {
                        error!(
                            "Proxy not found for ID: {}",
                            id
                        );
                        return;
                    }
                };

                let (proxy, _) = entry;

                proxy
                    .remove_user(&user.user_id.to_string())
                    .await;
            }
            None => {
                let mut users = self.users.write().await;
                users.remove(&user);
            }
        }
    }

    /// Seting Max bandwith for single proxy
    pub async fn set_max_bandwith(
        &self,
        proxy_id: &String,
        max: u64,
    ) {
        let entry = match self.get_proxy(proxy_id) {
            Some(entry) => entry,
            None => {
                error!(
                    "Proxy not found for ID: {}",
                    proxy_id
                );
                return;
            }
        };

        let (proxy, _) = entry;

        proxy.set_max_bandwith(max).await;
    }

    fn create_proxy_id() -> String {
        Uuid::new_v4().to_string()
    }
}
