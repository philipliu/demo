#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    BytesN, Env, Vec,
};

#[contract]
pub struct WalletContract;

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
}

#[contractimpl]
impl CustomAccountInterface for WalletContract {
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
