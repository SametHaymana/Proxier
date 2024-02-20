use serde::{Deserialize, Serialize};
use core::ascii;
use std::sync::{Arc, Mutex};

use actix_web::{
    web::{self, Data, Json},
    Responder,
};

use crate::proxy::Proxy;

#[derive(Deserialize, Serialize)]
pub struct AddBody {
    method: u8,
}

pub async fn list(
    proxy: Data<Arc<Mutex<Proxy>>>,
) -> impl Responder {
    format!("{:?}", proxy.lock().unwrap().list_auth_methods())
}

pub async fn add(
    proxy: Data<Arc<Mutex<Proxy>>>,
    data: Json<AddBody>,
) -> impl Responder {

    let mut p = proxy.lock().unwrap();

    p.add_method(data.method);

    format!("{:?}", p.list_auth_methods())
}

pub async fn remove(
    proxy: Data<Arc<Mutex<Proxy>>>,
    data: Json<AddBody>,
) -> impl Responder {
    let mut p = proxy.lock().unwrap();

    p.remove_method(data.method);

    format!("{:?}", p.list_auth_methods())
}

