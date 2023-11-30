//! Sample App for Passkeys

use base64::Engine;
use p256::ecdsa;
use passkey::{
    authenticator::{Authenticator, UserValidationMethod},
    client::{Client, WebauthnError},
    types::{ctap2::*, rand::random_vec, webauthn::*, Bytes, Passkey},
};

use coset::iana;
use serde::{Deserialize, Serialize};
use url::Url;
use utils::from_0x_hex;

// MyUserValidationMethod is a stub impl of the UserValidationMethod trait, used later.
struct MyUserValidationMethod {}
#[async_trait::async_trait]
impl UserValidationMethod for MyUserValidationMethod {
    async fn check_user_presence(&self) -> bool {
        true
    }

    async fn check_user_verification(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }
}

// Example of how to set up, register and authenticate with a `Client`.
async fn client_setup(
    challenge_bytes_from_rp: Bytes,
    parameters_from_rp: PublicKeyCredentialParameters,
    origin: &Url,
    user_entity: PublicKeyCredentialUserEntity,
) -> Result<(CreatedPublicKeyCredential, AuthenticatedPublicKeyCredential), WebauthnError> {
    // First create an Authenticator for the Client to use.
    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};
    // Create the CredentialStore for the Authenticator.
    // Option<Passkey> is the simplest possible implementation of CredentialStore
    let store: Option<Passkey> = None;
    let my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);

    // Create the Client
    // If you are creating credentials, you need to declare the Client as mut
    let mut my_client = Client::new(my_authenticator);

    // The following values, provided as parameters to this function would usually be
    // retrieved from a Relying Party according to the context of the application.
    let request = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: None, // Leaving the ID as None means use the effective domain
                name: origin.domain().unwrap().into(),
            },
            user: user_entity,
            challenge: challenge_bytes_from_rp.clone(),
            pub_key_cred_params: vec![parameters_from_rp],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    // Now create the credential.
    let my_webauthn_credential = my_client.register(origin, request, None).await?;

    println!("register finish");
    // Let's try and authenticate.
    // Create a challenge that would usually come from the RP.
    // let challenge_bytes_from_rp: Bytes = random_vec(32).into();
    // Now try and authenticate
    let credential_request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: challenge_bytes_from_rp,
            timeout: None,
            rp_id: Some(String::from(origin.domain().unwrap())),
            allow_credentials: None,
            user_verification: UserVerificationRequirement::default(),
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let authenticated_cred = my_client
        .authenticate(origin, credential_request, None)
        .await?;

    Ok((my_webauthn_credential, authenticated_cred))
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

#[derive(Serialize, Deserialize)]
pub struct PasskeyArgs {
    pub q_x: String,
    pub q_y: String,
    pub r: String,
    pub s: String,
    pub authenticator_data: String,
    pub client_data_jsonpre: String,
    pub client_data_jsonpost: String,
    pub args: String,
}

pub async fn generate_args(challenge: String) -> String {
    let rp_url = Url::parse("https://passkey.test.com").expect("Should Parse");
    let user_entity = PublicKeyCredentialUserEntity {
        id: random_vec(32).into(),
        display_name: "Passkey Tester".into(),
        name: "passkey@example.org".into(),
    };
    let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let challenge = from_0x_hex(&challenge).unwrap();
    println!("challenge: {}", base64url_engine.encode(&challenge));
    // Set up a client, create and authenticate a credential, then report results.
    let (created_cred, authed_cred) = client_setup(
        challenge.into(), // challenge_bytes_from_rp
        PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: iana::Algorithm::ES256,
        },
        &rp_url, // origin
        user_entity.clone(),
    )
    .await
    .unwrap();

    let client_data_json =
        String::from_utf8(authed_cred.response.client_data_json.to_vec()).unwrap();

    let index_a =
        index_of_sub_array(client_data_json.as_bytes(), r#"challenge":""#.as_bytes(), 0).unwrap();
    let index_b =
        index_of_sub_array(client_data_json.as_bytes(), r#"""#.as_bytes(), index_a + 12).unwrap();

    let client_data_json_pre = client_data_json[..index_a + 12].as_bytes().to_vec();
    let client_data_json_post = client_data_json[index_b..].as_bytes().to_vec();
    println!("client_data_json: {}", &client_data_json);

    let signature = ecdsa::Signature::from_der(authed_cred.response.signature.as_slice()).unwrap();

    let pk = created_cred.response.public_key.clone().unwrap();

    let args = [
        signature.r().to_bytes().as_slice(),
        signature.s().to_bytes().as_slice(),
        &(authed_cred.response.authenticator_data.len() as u32).to_be_bytes(),
        authed_cred.response.authenticator_data.as_slice(),
        &(client_data_json_pre.len() as u32).to_be_bytes(),
        &client_data_json_pre,
        &(client_data_json_post.len() as u32).to_be_bytes(),
        &client_data_json_post,
    ]
    .concat();

    let passkey_args = PasskeyArgs {
        q_x: hex::encode(&pk.as_slice()[27..59]),
        q_y: hex::encode(&pk.as_slice()[59..91]),
        r: hex::encode(signature.r().to_bytes()),
        s: hex::encode(signature.s().to_bytes()),
        authenticator_data: hex::encode(authed_cred.response.authenticator_data.as_slice()),
        client_data_jsonpre: String::from_utf8(client_data_json_pre).unwrap(),
        client_data_jsonpost: String::from_utf8(client_data_json_post).unwrap(),
        args: hex::encode(&args),
    };

    serde_json::to_string_pretty(&passkey_args).unwrap()
}
