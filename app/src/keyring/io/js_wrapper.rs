use crate::keyring::errors::KeyringError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "../js/scribe.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    fn check_exists(name: &str) -> Result<bool, JsValue>;
    #[wasm_bindgen(catch)]
    fn read_info(name: &str) -> Result<Uint8Array, JsValue>;
    #[wasm_bindgen(catch)]
    fn write_info(name: &str, contents: Uint8Array) -> Result<(), JsValue>;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(thing: &str);
}

pub fn write_to_js(name: &str, contents: &[u8]) -> Result<(), KeyringError> {
    let js_array = Uint8Array::new_with_length(contents.len() as u32);
    js_array.copy_from(contents);
    write_info(name, js_array)?;
    Ok(())
}

pub fn read_from_js(name: &str) -> Result<Vec<u8>, KeyringError> {
    let js_array = read_info(name).map_err(|e| KeyringError::from(e))?;
    
    return Ok(js_array.to_vec());
}

pub fn check_info_exists_in_js(name: &str) -> bool {
    return check_exists(name).unwrap_or(false);
}
