use std::io;

use async_trait::async_trait;

use super::proxy_manager::ProxyEx;

pub struct HttpProxy {}

#[async_trait]
impl ProxyEx for HttpProxy {
    async fn start(&self) -> Result<(), String> {
        todo!()
    }

    async fn set_avaliable_auth_methods(
        &mut self,
        methods: Vec<u8>,
    ) {
        todo!()
    }

    async fn avaliable_auth_methods(&self) -> Vec<u8> {
        todo!()
    }

    async fn avaliable_users(
        &self,
    ) -> std::sync::Arc<
        parking_lot::RwLock<
            std::collections::HashSet<
                std::sync::Arc<crate::models::users::User>,
            >,
        >,
    > {
        todo!()
    }

    async fn set_user(
        &mut self,
        user: std::sync::Arc<crate::models::users::User>,
    ) {
        todo!()
    }

    async fn remove_user(&mut self, user_id: &str) -> bool {
        todo!()
    }
}

impl HttpProxy {
    pub fn new() -> Self {
        HttpProxy {}
    }
}
