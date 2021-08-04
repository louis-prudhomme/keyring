use wasm_bindgen::prelude::wasm_bindgen;

extern crate console_error_panic_hook;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Cred {
    pub(crate) login: String,
    pub(crate) pass: String,
}

#[wasm_bindgen]
impl Cred {
    pub fn from(login: String, pass: String) -> Cred {
        console_error_panic_hook::set_once();
        return Cred { login, pass };
    }
}