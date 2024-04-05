use serde::{Deserialize, Serialize};
use core::ascii;
use std::sync::{Arc, Mutex};

use actix_web::{
    web::{self, Data, Json},
    Responder,
};

use crate::proxy::Proxy;

/*
#[derive(Deserialize, Serialize)]
pub struct AddBody {
    method: u8,
}

pub async fn list(
    proxy: Data<Arc<Proxy>>,
) -> impl Responder {
    format!("{:?}", proxy.list_auth_methods())
}

pub async fn add(
    proxy: Data<Arc<Proxy>>,
    data: Json<AddBody>,
) -> impl Responder {
    proxy.clone().add_method(data.method);
    format!("{:?}", proxy.list_auth_methods())
}


pub async fn remove(
    proxy: Data<Proxy>,
    data: Json<AddBody>,
) -> impl Responder {
    proxy.remove_method(data.method);
    format!("{:?}", p.list_auth_methods())
}

*/