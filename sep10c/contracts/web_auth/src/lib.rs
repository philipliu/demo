#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};
use soroban_sdk::{contracterror, Map, String};

#[contract]
pub struct WebAuthContract;

#[contracterror]
#[derive(Clone, Copy)]
pub enum WebAuthError {
    WebAuthBadAddress = 1,
}

#[contractimpl]
impl WebAuthContract {
    pub fn web_auth_verify(env: Env, args: Map<String, String>) -> Result<(), WebAuthError> {
        if let Some(account_id) = args.get(String::from_str(&env, "account")) {
            let addr = Address::from_string(&account_id);
            addr.require_auth();
        } else {
            return Err(WebAuthError::WebAuthBadAddress);
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

mod test;
