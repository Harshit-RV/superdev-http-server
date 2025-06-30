use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use base64;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bs58;
use serde::{Deserialize, Serialize};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::signature::Signature;
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
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

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: Option<SignMessageData>,
    error: Option<String>,
}

#[post("/message/sign")]
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 secret key".to_string()),
            });
        }
    };

    if secret_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("Secret key must be 64 bytes (base58-encoded)".to_string()),
        });
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Failed to parse secret key".to_string()),
            });
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    let data = SignMessageData {
        signature: STANDARD.encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
        message: req.message.clone(),
    };

    HttpResponse::Ok().json(SignMessageResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String, // base64
    pubkey: String,    // base58
}

#[derive(Serialize)]
struct VerifyData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: Option<VerifyData>,
    error: Option<String>,
}

#[post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    let result = (|| {
        let pubkey = Pubkey::from_str(&req.pubkey)?;
        let sig_bytes = STANDARD.decode(&req.signature)?;
        let signature = Signature::try_from(&sig_bytes[..])?;
        let is_valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

        Ok::<_, Box<dyn std::error::Error>>(VerifyMessageResponse {
            success: true,
            data: Some(VerifyData {
                valid: is_valid,
                message: req.message.clone(),
                pubkey: req.pubkey.clone(),
            }),
            error: None,
        })
    })();

    match result {
        Ok(res) => HttpResponse::Ok().json(res),
        Err(e) => HttpResponse::BadRequest().json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(greet)
            .service(greet_post)
            .service(create_token)
            .service(sign_message)
            .service(verify_message)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
