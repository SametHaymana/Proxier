use std::{collections::HashSet, io};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::proxy_manager::ProxyEx;

#[derive(Debug)]
pub struct HttpProxy {}

/*
#[async_trait]
impl ProxyEx for HttpProxy {
    async fn start(&self) -> Result<(), String> {
        todo!()
    }

    async fn avaliable_auth_methods(&self) -> HashSet<u8> {
        todo!()
    }

    async fn set_avaliable_auth_method(
        &self,
        methods: Vec<u8>,
    ) {
        todo!()
    }

    async fn remove_avaliable_auth_method(
        &self,
        methods: Vec<u8>,
    ) {
        todo!()
    }

    async fn avaliable_users(
        &self,
    ) -> std::collections::HashSet<crate::models::users::User>
    {
        todo!()
    }

    async fn set_user(
        &self,
        user: crate::models::users::User,
    ) {
        todo!()
    }

    async fn remove_user(&self, user_id: &str) -> bool {
        todo!()
    }
}

*/
impl HttpProxy {
    pub fn new() -> Self {
        HttpProxy {}
    }
}
