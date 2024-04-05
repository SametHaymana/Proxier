use serde::{Deserialize, Serialize};
use actix_web::{
    web::{self, Data, Json},
    Responder,
};

use super::proxy;

#[derive(Deserialize, Serialize)]
pub struct  User{
    username: String,
    password: String
}
#[derive(Deserialize, Serialize)]
pub struct  ListParam{
    page: i32,
    pageSize: i32
}

/*
    fn async listIdents(
        proxy: Data<ArcProxy>>,
        query: web::Query<ListParam>
    ) -> impl Responder
    {
        proxy.

    }
*/