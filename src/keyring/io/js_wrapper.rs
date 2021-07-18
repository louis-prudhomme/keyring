use crate::keyring::errors::KeyringError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/js/scribe.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    fn read_info(name: &str) -> Result<String, JsValue>;
    #[wasm_bindgen(catch)]
    fn write_info(name: &str, contents: &str) -> Result<(), JsValue>;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(thing: &str);
}

pub fn write_info_to_js(name: &str, contents: &str) -> Result<(), KeyringError> {
    write_info(name, contents)?;
    Ok(())
}

pub fn read_info_from_js(name: &str) -> Result<String, KeyringError> {
    return read_info(name).map_err(|e| KeyringError::from(e));
}

pub fn check_info_exists_in_js(name: &str) -> bool {
    return read_info_from_js(name).is_ok();
}
