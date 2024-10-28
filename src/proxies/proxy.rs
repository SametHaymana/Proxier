use async_trait::async_trait;

use std::sync::{Arc, RwLock};

use crate::models::users::{User, UserId};

#[async_trait]
pub trait Proxy {
    /*

        Proxy server Users information

    */
    async fn get_users() -> Arc<RwLock<Vec<User>>>;

    async fn register_user(user: User) -> bool;

    async fn remove_user(user_id: UserId) -> bool;
}
