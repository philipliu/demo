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
    pub fn web_auth_verify(
        env: Env,
        address: String,               // TODO: use Address
        _memo: String,                 // IGNORED
        _home_domain: String,          // IGNORED
        _web_auth_domain: String,      // IGNORED
        _client_domain: String,        // IGNORED
        client_domain_address: String, // TODO: use Address
    ) -> Result<(), WebAuthError> {
        let addr = Address::from_string(&address);
        addr.require_auth();
        Ok(())
    }
}

mod test;
