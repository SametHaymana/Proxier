// src/api/app.rs

use std::sync::{Arc, Mutex};

use crate::proxy::Proxy;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

use super::routers::routers;

pub async fn app(proxy: Arc<Proxy>) -> std::io::Result<()> {
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_method()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(proxy.clone()))
            .configure(routers.clone())
    });

    println!("Server Runing at 127.0.0.1:8888");

    server.bind("127.0.0.1:8888")?.run().await
}
