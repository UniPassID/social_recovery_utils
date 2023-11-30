use std::{io::Write, time::Duration};

use base64::Engine;
use ethers::abi::{Token, Tokenizable};
use jwt_simple::prelude::*;
use num_bigint_dig::BigUint;

use utils::to_0x_hex;

#[derive(Serialize, Deserialize)]
pub struct OpenIDArgs {
    pub pk: String,
    pub kid: String,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub nonce: String,
    pub args: String,
}

pub fn generate_idtoken(
    keypair: &RS256KeyPair,
    iss: &str,
    sub: &str,
    aud: &str,
    nonce: &str,
) -> String {
    let claims = Claims::create(Duration::from_secs(86400).into())
        .with_issuer(iss)
        .with_nonce(nonce)
        .with_audience(aud)
        .with_subject(sub);

    return keypair.sign(claims).unwrap();
}

pub fn genearate_sk(create: bool, sk_path: String) -> RS256KeyPair {
    if create {
        let keypair = RS256KeyPair::generate(2048).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&sk_path)
            .unwrap();
        file.write(keypair.to_pem().unwrap().as_bytes()).unwrap();
        file.flush().unwrap();
        keypair
    } else {
        let sk_pem = std::fs::read_to_string(&sk_path).unwrap();
        RS256KeyPair::from_pem(&sk_pem).unwrap()
    }
}

pub fn generate_args(
    create: bool,
    sk_path: String,
    kid: String,
    iss: String,
    sub: String,
    aud: String,
    nonce: String,
) -> String {
    let mut keypair = genearate_sk(create, sk_path);

    if kid.len() > 0 {
        keypair = keypair.with_key_id(&kid);
    }

    let id_token = generate_idtoken(&keypair, &iss, &sub, &aud, &nonce);

    return generate_contract_args(&keypair, id_token, kid, iss, sub, aud, nonce);
}

pub fn generate_contract_args(
    keypair: &RS256KeyPair,
    id_token: String,
    kid: String,
    iss: String,
    sub: String,
    aud: String,
    nonce: String,
) -> String {
    let id_toeken_split: Vec<_> = id_token.split(".").collect();
    if id_toeken_split.len() != 3 {
        panic!("invalid id_token")
    }
    let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = base64url_engine
        .decode(id_toeken_split[0].as_bytes())
        .unwrap();
    let payload = base64url_engine
        .decode(id_toeken_split[1].as_bytes())
        .unwrap();
    let signature = base64url_engine
        .decode(id_toeken_split[2].as_bytes())
        .unwrap();

    println!("header: {}", String::from_utf8_lossy(&header));
    println!("payload: {}", String::from_utf8_lossy(&payload));

    let field_end_value = r#"","#.as_bytes();
    let obj_end_value = r#""}"#.as_bytes();

    let iss_left_index = index_of_sub_array(&payload, r#""iss":""#.as_bytes(), 0).unwrap() + 7;
    let iss_right_index = match index_of_sub_array(&payload, field_end_value, iss_left_index) {
        Some(iss_right_index) => iss_right_index,
        None => index_of_sub_array(&payload, obj_end_value, iss_left_index).unwrap(),
    };

    let kid_left_index = index_of_sub_array(&header, r#""kid":""#.as_bytes(), 0).unwrap() + 7;
    let kid_right_index = match index_of_sub_array(&header, field_end_value, kid_left_index) {
        Some(kid_right_index) => kid_right_index,
        None => index_of_sub_array(&header, obj_end_value, kid_left_index).unwrap(),
    };

    let iat_left_index = index_of_sub_array(&payload, r#""iat":"#.as_bytes(), 0).unwrap() + 6;
    let exp_left_index = index_of_sub_array(&payload, r#""exp":"#.as_bytes(), 0).unwrap() + 6;

    let sub_left_index = index_of_sub_array(&payload, r#""sub":""#.as_bytes(), 0).unwrap() + 7;
    let sub_right_index = match index_of_sub_array(&payload, field_end_value, sub_left_index) {
        Some(sub_right_index) => sub_right_index,
        None => index_of_sub_array(&payload, obj_end_value, sub_left_index).unwrap(),
    };

    let aud_left_index = index_of_sub_array(&payload, r#""aud":""#.as_bytes(), 0).unwrap() + 7;
    let aud_right_index = match index_of_sub_array(&payload, field_end_value, aud_left_index) {
        Some(aud_right_index) => aud_right_index,
        None => index_of_sub_array(&payload, obj_end_value, aud_left_index).unwrap(),
    };

    let nonce_left_index = index_of_sub_array(&payload, r#""nonce":""#.as_bytes(), 0).unwrap() + 9;

    let data = ethers::abi::encode_packed(&[
        (iss_left_index as u32).to_be_bytes().into_token(),
        (iss_right_index as u32).to_be_bytes().into_token(),
        (kid_left_index as u32).to_be_bytes().into_token(),
        (kid_right_index as u32).to_be_bytes().into_token(),
        (sub_left_index as u32).to_be_bytes().into_token(),
        (sub_right_index as u32).to_be_bytes().into_token(),
        (aud_left_index as u32).to_be_bytes().into_token(),
        (aud_right_index as u32).to_be_bytes().into_token(),
        (nonce_left_index as u32).to_be_bytes().into_token(),
        (iat_left_index as u32).to_be_bytes().into_token(),
        (exp_left_index as u32).to_be_bytes().into_token(),
        (header.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(header),
        (payload.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(payload),
        (signature.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(signature),
    ])
    .unwrap();

    let pk_comp = keypair.public_key().public_key().to_components();
    return serde_json::to_string_pretty(&OpenIDArgs {
        pk: BigUint::from_bytes_be(&pk_comp.n).to_str_radix(16),
        kid,
        iss,
        sub,
        aud,
        nonce,
        args: to_0x_hex(data),
    })
    .unwrap();
}

fn index_of_sub_array(array: &[u8], sub_array: &[u8], start: usize) -> Option<usize> {
    if sub_array.is_empty() {
        return None;
    }
    array[start..]
        .windows(sub_array.len())
        .position(|window| window == sub_array)
        .map(|v| v + start)
}

#[test]
fn test_mock_idtoken() {
    let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // create a new key for the `HS256` JWT algorithm
    let key = RS256KeyPair::generate(2048).unwrap();
    let key = key.with_key_id("255cca6ec2810602d80bec89e456c4495d7418bb");

    let pk_comp = key.public_key().public_key().to_components();
    println!(
        "public key: \n 0x{:?},\n 0x{:?}",
        BigUint::from_bytes_be(&pk_comp.e).to_str_radix(16),
        BigUint::from_bytes_be(&pk_comp.n).to_str_radix(16)
    );
    let claims = Claims::create(Duration::from_secs(86400).into())
        .with_issuer("https://accounts.google.com")
        .with_nonce("1234567890")
        .with_audience("123456")
        .with_subject("104331660410164053021");
    let id_token = key.sign(claims).unwrap();

    let id_tokens: Vec<_> = id_token.split('.').collect();
    let header_base64_bytes = id_tokens[0].as_bytes().to_vec();
    let payload_base64_bytes = id_tokens[1].as_bytes().to_vec();

    let payload_raw_bytes = base64url_engine.decode(&payload_base64_bytes).unwrap();
    let header_raw_bytes = base64url_engine.decode(&header_base64_bytes).unwrap();

    println!("header: {}", String::from_utf8_lossy(&header_raw_bytes));
    println!("payload: {}", String::from_utf8_lossy(&payload_raw_bytes));
}
