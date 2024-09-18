#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl, contracttype,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};
use soroban_sdk::{contracterror, Map, String};

#[contract]
pub struct CustomAccountContract;

#[contracttype]
#[derive(Clone)]
pub struct AccSignature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracterror]
#[derive(Clone, Copy)]
pub enum AccError {
    UnknownSigner = 1,
    BadSignatureOrder = 2,
    InvalidContext = 3,
    WebAuthBadAddress = 4,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    SignerCnt,
    Signer(BytesN<32>),
}

#[contractimpl]
impl CustomAccountContract {
    pub fn init(env: Env, signers: Vec<BytesN<32>>) {
        // Add signers
        for signer in signers.iter() {
            env.storage().instance().set(&DataKey::Signer(signer), &());
        }
        env.storage()
            .instance()
            .set(&DataKey::SignerCnt, &signers.len());
    }

    pub fn web_auth_verify(env: Env, args: Map<String, String>) -> Result<(), AccError> {
        if let Some(account_id) = args.get(String::from_str(&env, "account")) {
            let addr = Address::from_string(&account_id);
            addr.require_auth();
        } else {
            return Err(AccError::WebAuthBadAddress);
        };
        Ok(())
    }
}

#[contractimpl]
impl CustomAccountInterface for CustomAccountContract {
    type Signature = Vec<AccSignature>;
    type Error = AccError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Vec<AccSignature>,
        auth_context: Vec<Context>,
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
        if !env
            .storage()
            .instance()
            .has(&DataKey::Signer(signature.public_key.clone()))
        {
            return Err(AccError::UnknownSigner);
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
