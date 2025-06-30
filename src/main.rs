use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bs58;
use serde::{Deserialize, Serialize};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::signature::{Keypair, Signer};
use spl_token::instruction::initialize_mint;
use std::str::FromStr;

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

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaJson {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionJson {
    program_id: String,
    accounts: Vec<AccountMetaJson>,
    instruction_data: String,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: InstructionJson,
}

#[post("/token/create")]
async fn create_token(req: web::Json<CreateTokenRequest>) -> impl Responder {
    let result = (|| -> Result<CreateTokenResponse, Box<dyn std::error::Error>> {
        let mint_pubkey = Pubkey::from_str(&req.mint)?;
        let mint_authority_pubkey = Pubkey::from_str(&req.mintAuthority)?;

        let ix: Instruction = initialize_mint(
            &spl_token::id(),
            &mint_pubkey,
            &mint_authority_pubkey,
            None,
            req.decimals,
        )?;

        let accounts: Vec<AccountMetaJson> = ix
            .accounts
            .iter()
            .map(|meta| AccountMetaJson {
                pubkey: meta.pubkey.to_string(),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect();

        Ok(CreateTokenResponse {
            success: true,
            data: InstructionJson {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: STANDARD.encode(ix.data),
            },
        })
    })();

    match result {
        Ok(res) => HttpResponse::Ok().json(res),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(greet)
            .service(greet_post)
            .service(create_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
