use actix_web::{App, HttpServer, Responder, get, post, web};
use serde::Deserialize;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

#[derive(Deserialize)]
struct NamePayload {
    name: String,
}

#[post("/hello")]
async fn greet_post(payload: web::Json<NamePayload>) -> impl Responder {
    format!("Hello {}!", payload.name)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(greet).service(greet_post))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
