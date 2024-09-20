#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl, contracttype,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};
use soroban_sdk::{contracterror, Map, String};

#[contract]
pub struct WebAuthContract;

#[contracttype]
#[derive(Clone)]
pub struct AccSignature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracterror]
#[derive(Clone, Copy)]
pub enum AccError {
    BadSignatureOrder = 1,
    InvalidContext = 2,
    WebAuthBadAddress = 3,
}

#[contractimpl]
impl WebAuthContract {
    // TODO: do we need to support multiple signer types?
    pub fn web_auth_verify(env: Env, args: Map<String, String>) -> Result<(), AccError> {
        if let Some(account_id) = args.get(String::from_str(&env, "account")) {
            let addr = Address::from_string(&account_id);
            addr.require_auth();
        } else {
            return Err(AccError::WebAuthBadAddress);
        };

        if let Some(client_domain_signing_key) =
            args.get(String::from_str(&env, "client_domain_signing_key"))
        {
            // TODO: only allow ed25519 signers
            let addr = Address::from_string(&client_domain_signing_key);
            addr.require_auth();
        }

        Ok(())
    }
}

#[contractimpl]
impl CustomAccountInterface for WebAuthContract {
    type Signature = Vec<AccSignature>;
    type Error = AccError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Vec<AccSignature>,
        _auth_context: Vec<Context>,
    ) -> Result<(), AccError> {
        authenticate(&env, &signature_payload, &signatures)?;

        Ok(())
    }
}

fn authenticate(
    env: &Env,
    signature_payload: &Hash<32>,
    signatures: &Vec<AccSignature>,
) -> Result<(), AccError> {
    for i in 0..signatures.len() {
        let signature = signatures.get_unchecked(i);
        if i > 0 {
            let prev_signature = signatures.get_unchecked(i - 1);
            if prev_signature.public_key >= signature.public_key {
                return Err(AccError::BadSignatureOrder);
            }
        }

        env.crypto().ed25519_verify(
            &signature.public_key,
            &signature_payload.clone().into(),
            &signature.signature,
        );
    }
    Ok(())
}

mod test;
