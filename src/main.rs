use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use base64;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bs58;
use serde::{Deserialize, Serialize};
use solana_program::{instruction::Instruction, pubkey::Pubkey, system_instruction};
use solana_sdk::signature::Signature;
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use spl_token::instruction::initialize_mint;
use spl_token::instruction::mint_to;
use spl_token::instruction::transfer;
use std::str::FromStr;

fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, &'static str> {
    Pubkey::from_str(pubkey_str).map_err(|_| "Invalid public key format")
}

fn validate_secret_key(secret_str: &str) -> Result<Vec<u8>, &'static str> {
    let secret_bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid base58 secret key")?;

    if secret_bytes.len() != 64 {
        return Err("Secret key must be 64 bytes");
    }

    Ok(secret_bytes)
}

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
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
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
        if req.mint_authority.is_empty() || req.mint.is_empty() {
            return Err("Missing required fields".into());
        }

        let mint_pubkey = validate_pubkey(&req.mint)?;
        let mint_authority_pubkey = validate_pubkey(&req.mint_authority)?;

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
                instruction_data: STANDARD.encode(ix.data.as_slice()),
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
    data: SignMessageData,
}

#[post("/message/sign")]
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    let result = (|| -> Result<SignMessageResponse, Box<dyn std::error::Error>> {
        if req.message.is_empty() || req.secret.is_empty() {
            return Err("Missing required fields".into());
        }

        let secret_bytes = validate_secret_key(&req.secret)?;

        let keypair =
            Keypair::from_bytes(&secret_bytes).map_err(|_| "Failed to parse secret key")?;

        let signature = keypair.sign_message(req.message.as_bytes());

        Ok(SignMessageResponse {
            success: true,
            data: SignMessageData {
                signature: STANDARD.encode(signature.as_ref()),
                public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
                message: req.message.clone(),
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
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
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
    data: VerifyData,
}

#[post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    let result = (|| -> Result<VerifyMessageResponse, Box<dyn std::error::Error>> {
        if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
            return Err("Missing required fields".into());
        }

        let pubkey = validate_pubkey(&req.pubkey)?;
        let sig_bytes = STANDARD
            .decode(&req.signature)
            .map_err(|_| "Invalid base64 signature")?;
        let signature =
            Signature::try_from(&sig_bytes[..]).map_err(|_| "Invalid signature format")?;

        let is_valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

        Ok(VerifyMessageResponse {
            success: true,
            data: VerifyData {
                valid: is_valid,
                message: req.message.clone(),
                pubkey: req.pubkey.clone(),
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
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponse {
    success: bool,
    data: InstructionJson,
}

#[post("/token/mint")]
async fn mint_token(req: web::Json<MintTokenRequest>) -> impl Responder {
    let result = (|| -> Result<MintTokenResponse, Box<dyn std::error::Error>> {
        if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
            return Err("Missing required fields".into());
        }

        if req.amount == 0 {
            return Err("Amount must be greater than 0".into());
        }

        let mint = validate_pubkey(&req.mint)?;
        let destination = validate_pubkey(&req.destination)?;
        let authority = validate_pubkey(&req.authority)?;

        let ix = mint_to(
            &spl_token::id(),
            &mint,
            &destination,
            &authority,
            &[],
            req.amount,
        )?;

        let accounts = ix
            .accounts
            .iter()
            .map(|meta| AccountMetaJson {
                pubkey: meta.pubkey.to_string(),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect();

        Ok(MintTokenResponse {
            success: true,
            data: InstructionJson {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: STANDARD.encode(ix.data.as_slice()),
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
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: SendSolData,
}

#[post("/send/sol")]
async fn send_sol(req: web::Json<SendSolRequest>) -> impl Responder {
    let result = (|| -> Result<SendSolResponse, Box<dyn std::error::Error>> {
        if req.from.is_empty() || req.to.is_empty() {
            return Err("Missing required fields".into());
        }

        if req.lamports == 0 {
            return Err("Lamports must be greater than 0".into());
        }

        let from_pubkey = validate_pubkey(&req.from)?;
        let to_pubkey = validate_pubkey(&req.to)?;

        let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

        let accounts: Vec<String> = ix
            .accounts
            .iter()
            .map(|meta| meta.pubkey.to_string())
            .collect();

        Ok(SendSolResponse {
            success: true,
            data: SendSolData {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: STANDARD.encode(ix.data.as_slice()),
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
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: SendTokenData,
}

#[post("/send/token")]
async fn send_token(req: web::Json<SendTokenRequest>) -> impl Responder {
    let result = (|| -> Result<SendTokenResponse, Box<dyn std::error::Error>> {
        if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
            return Err("Missing required fields".into());
        }

        if req.amount == 0 {
            return Err("Amount must be greater than 0".into());
        }

        let destination = validate_pubkey(&req.destination)?;
        let mint = validate_pubkey(&req.mint)?;
        let owner = validate_pubkey(&req.owner)?;

        let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);

        let ix = transfer(
            &spl_token::id(),
            &source,
            &destination,
            &owner,
            &[],
            req.amount,
        )?;

        let accounts = ix
            .accounts
            .iter()
            .map(|meta| SendTokenAccountMeta {
                pubkey: meta.pubkey.to_string(),
                is_signer: meta.is_signer,
            })
            .collect();

        Ok(SendTokenResponse {
            success: true,
            data: SendTokenData {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: STANDARD.encode(ix.data.as_slice()),
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
            .service(sign_message)
            .service(verify_message)
            .service(mint_token)
            .service(send_sol)
            .service(send_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
