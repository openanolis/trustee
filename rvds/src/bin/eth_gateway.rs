use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use hex::FromHex;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use web3::{
    transports::Http,
    types::{Address, Bytes, TransactionParameters, H160, U256},
    Web3,
};

#[derive(Deserialize)]
struct RecordRequest {
    event_hash: String, // hex string 0x...
    payload: String,    // canonical JSON string
}

#[derive(Serialize)]
struct RecordResponse {
    tx_hash: String,
}

/// ABI for function record(bytes32,string)
fn record_function() -> Function {
    Function {
        name: "record".to_string(),
        inputs: vec![
            Param {
                name: "eventHash".to_string(),
                kind: ParamType::FixedBytes(32),
                internal_type: None,
            },
            Param {
                name: "payloadHash".to_string(),
                kind: ParamType::String,
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    }
}

#[post("/record")]
async fn record(body: web::Json<RecordRequest>, data: web::Data<AppState>) -> impl Responder {
    // Hash payload；链上仅写入摘要，原文不直接上链
    let payload_hash = hex::encode(Sha256::digest(body.payload.as_bytes()));

    // Decode event_hash
    let event_bytes = match Vec::from_hex(body.event_hash.trim_start_matches("0x")) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("invalid event_hash: {e}"));
        }
    };
    if event_bytes.len() != 32 {
        return HttpResponse::BadRequest().body(format!(
            "event_hash must be 32 bytes, got {}",
            event_bytes.len()
        ));
    }

    // Build call data
    let func = record_function();
    let call_data = match func.encode_input(&[
        Token::FixedBytes(event_bytes.clone()),
        Token::String(payload_hash.clone()), // 仅上链哈希，降低 gas
    ]) {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().body(format!("encode abi: {e}")),
    };

    // Prepare tx params
    let web3 = &data.web3;
    let from: H160 = data.from;
    let nonce = match web3.eth().transaction_count(from, None).await {
        Ok(n) => n,
        Err(e) => return HttpResponse::InternalServerError().body(format!("nonce error: {e}")),
    };

    let gas_price = match web3.eth().gas_price().await {
        Ok(p) => p,
        Err(e) => return HttpResponse::InternalServerError().body(format!("gas_price error: {e}")),
    };

    let tx = TransactionParameters {
        to: Some(data.contract),
        gas_price: Some(gas_price),
        gas: U256::from(200_000u64),
        value: U256::zero(),
        data: Bytes(call_data),
        nonce: Some(nonce),
        ..Default::default()
    };

    let signed = match web3.accounts().sign_transaction(tx, &data.sk).await {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("sign error: {e}")),
    };

    let pending = match web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await
    {
        Ok(p) => p,
        Err(e) => return HttpResponse::InternalServerError().body(format!("send tx error: {e}")),
    };

    HttpResponse::Ok().json(RecordResponse {
        tx_hash: format!("{:#x}", pending),
    })
}

struct AppState {
    web3: Web3<Http>,
    sk: SecretKey,
    from: Address,
    contract: Address,
}

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    env_logger::init();
    let listen = env::var("ETH_GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8095".to_string());
    let rpc = env::var("ETH_RPC_URL").expect("ETH_RPC_URL is required");
    let pk_hex = env::var("ETH_PRIVATE_KEY").expect("ETH_PRIVATE_KEY is required (0x...)");
    let contract_addr = env::var("ETH_CONTRACT_ADDRESS").expect("ETH_CONTRACT_ADDRESS required");
    let sk = SecretKey::from_slice(
        &hex::decode(pk_hex.trim_start_matches("0x")).expect("invalid ETH_PRIVATE_KEY hex"),
    )
    .expect("invalid ETH_PRIVATE_KEY");
    let from: Address = H160::from_slice(
        &web3::signing::keccak256(
            &secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
                .serialize_uncompressed()[1..],
        )[12..],
    );
    let contract: Address = contract_addr.parse().expect("invalid ETH_CONTRACT_ADDRESS");
    let transport = web3::transports::Http::new(&rpc).expect("invalid ETH_RPC_URL");
    let web3 = Web3::new(transport);

    let state = web::Data::new(AppState {
        web3,
        sk,
        from,
        contract,
    });

    println!("Starting eth-gateway real on {listen}, from={from:?}, contract={contract:?}");
    HttpServer::new(move || App::new().app_data(state.clone()).service(record))
        .bind(listen)?
        .run()
        .await
}
