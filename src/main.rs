use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};

#[derive(Serialize)]
struct Greeting {
    message: String,
}

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    let response = Greeting {
        message: format!("Hello {}!", name),
    };
    web::Json(response)
}

#[derive(Serialize)]
struct GenerateKeypairResponse {
    success: bool,
    data: GenerateKeypairData,
}

#[derive(Serialize)]
struct GenerateKeypairData {
    pubkey: String,
    secret: String,
}

#[post("/keypair")]
async fn greet_post() -> Result<impl Responder, actix_web::Error> {
    let result = (|| {
        let keypair = Keypair::new();

        Ok::<_, Box<dyn std::error::Error>>(GenerateKeypairResponse {
            success: true,
            data: GenerateKeypairData {
                pubkey: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
                secret: bs58::encode(keypair.to_bytes()).into_string(),
            },
        })
    })();

    match result {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            let error_message = format!("Keypair generation failed: {}", e);
            let error_response = HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": error_message
            }));
            Ok(error_response)
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(greet).service(greet_post))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
