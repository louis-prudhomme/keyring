use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
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

pub fn gen_rand_string(length: usize) -> String {
    return thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
}
