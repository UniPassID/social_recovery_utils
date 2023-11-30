use std::io::Write;

use error::ParserError;
use ethers::abi::{Token, Tokenizable};
use lettre::message::{DkimSigningAlgorithm, DkimSigningKey};
use mock::construct_email;
use parser::parse_email;
use rand::thread_rng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use utils::to_0x_hex;

pub mod error;
pub mod mock;
pub mod parser;
pub mod types;

pub type ParserResult<T> = Result<T, ParserError>;

#[derive(Serialize, Deserialize)]
pub struct EmailArgs {
    pub pk: String,
    pub from: String,
    pub subject: String,
    pub args: String,
}

pub fn generate_args(
    create: bool,
    sk_path: String,
    from: String,
    to: String,
    subject: String,
    body: String,
    selector: String,
    domain: String,
) -> String {
    let (signing_key, public_key) = genearate_sk(create, sk_path);
    let email = construct_email(
        from.clone(),
        to,
        subject.clone(),
        body,
        selector,
        domain,
        signing_key,
    );
    let params = parse_email(&email).unwrap();

    println!("{}", serde_json::to_string_pretty(&params).unwrap());

    let args = ethers::abi::encode_packed(&[
        (0u8).to_be_bytes().into_token(),
        (params.subject_index as u32).to_be_bytes().into_token(),
        (params.subject_right_index as u32)
            .to_be_bytes()
            .into_token(),
        (params.from_index as u32).to_be_bytes().into_token(),
        (params.from_left_index as u32).to_be_bytes().into_token(),
        (params.from_right_index as u32).to_be_bytes().into_token(),
        (params.dkim_header_index as u32).to_be_bytes().into_token(),
        (params.selector_index as u32).to_be_bytes().into_token(),
        (params.selector_right_index as u32)
            .to_be_bytes()
            .into_token(),
        (params.sdid_index as u32).to_be_bytes().into_token(),
        (params.sdid_right_index as u32).to_be_bytes().into_token(),
        (params.email_header.len() as u32)
            .to_be_bytes()
            .into_token(),
        Token::Bytes(params.email_header),
        (params.dkim_sig.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(params.dkim_sig),
    ])
    .unwrap();

    println!("{}", to_0x_hex(&args));

    return serde_json::to_string_pretty(&EmailArgs {
        pk: public_key.n().to_str_radix(16),
        from,
        subject,
        args: to_0x_hex(args),
    })
    .unwrap();
}

pub fn genearate_sk(create: bool, sk_path: String) -> (DkimSigningKey, RsaPublicKey) {
    if create {
        let mut rng = thread_rng();
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_key = rsa_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let keypair = DkimSigningKey::new(&private_key, DkimSigningAlgorithm::Rsa).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&sk_path)
            .unwrap();
        file.write(private_key.as_bytes()).unwrap();
        file.flush().unwrap();
        (keypair, rsa_key.to_public_key())
    } else {
        let sk_pem = std::fs::read_to_string(&sk_path).unwrap();
        let rsa_key = RsaPrivateKey::from_pkcs1_pem(&sk_pem).unwrap();
        (
            DkimSigningKey::new(&sk_pem, DkimSigningAlgorithm::Rsa).unwrap(),
            rsa_key.to_public_key(),
        )
    }
}

#[test]
fn test_gen_email() {
    let (signing_key, _public_key) = genearate_sk(true, "email.sk".to_string());
    let email = construct_email(
        "Alice <alice@test.com>".to_string(),
        "Bob <bob@test.com>".to_string(),
        "0x12345678".to_string(),
        "test email".to_string(),
        "s2023".to_string(),
        "test.com".to_string(),
        signing_key,
    );
    let params = parse_email(&email).unwrap();

    println!("{}", serde_json::to_string_pretty(&params).unwrap());
    println!("{}", String::from_utf8_lossy(&email));
}
