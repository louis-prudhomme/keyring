use crate::KEY_LENGTH;
use crate::keyring::constants::Key;
use crate::keyring::constants::IV;
use crate::keyring::constants::IV_LENGTH;
use rand::{thread_rng, RngCore};
use wasm_bindgen::prelude::*;

extern crate console_error_panic_hook;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Cred {
    pub(crate) login: String,
    pub(crate) pass: String,
}

#[wasm_bindgen]
impl Cred {
    pub fn new(login: String, pass: String) -> Cred {
        console_error_panic_hook::set_once();
        return Cred { login, pass };
    }
}

//todo create generic fn
pub fn gen_rand_iv() -> IV {
    let mut buf = [0u8; IV_LENGTH];
    thread_rng().fill_bytes(&mut buf);
    return buf;
}

pub fn gen_rand_key() -> Key {
    let mut buf = [0u8; KEY_LENGTH];
    thread_rng().fill_bytes(&mut buf);
    return buf;
}
