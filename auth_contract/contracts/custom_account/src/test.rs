#![cfg(test)]

use super::*;
use soroban_sdk::Env;

#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register_contract(None, CustomAccountContract);
    let client = CustomAccountContractClient::new(&env, &contract_id);

    todo!()
}
