use actix_web::web;

use super::controllers::proxy;

pub fn routers(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api").service(
            web::scope("/proxy")
                .route("", web::get().to(proxy::list))
                .route("", web::post().to(proxy::add))
                .route("", web::delete().to(proxy::remove)),
        ),
    );
}
