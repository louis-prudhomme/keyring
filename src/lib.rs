// The wasm-pack uses wasm-bindgen to build and generate JavaScript binding file.
// Import the wasm-bindgen crate.
mod keyring;

use crate::keyring::constants::*;
use crate::keyring::cred::Cred;
use crate::keyring::cryptutils::*;
use crate::keyring::errors::*;
use crate::keyring::io::read::*;
use crate::keyring::io::write::*;

use std::panic;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate serde_derive;

/// Checks whether a password database already exists.
#[wasm_bindgen]
pub fn check_db_exists() -> bool {
    console_error_panic_hook::set_once();
    return check_db_file_exists();
}

/// Creates an empty password database and returns true upon success.
#[wasm_bindgen]
pub fn sign_up(user_cred: Cred) -> Result<bool, JsValue> {
    // if db exist, then error
    if check_db_exists() {
        panic!("Database already exists");
    }
    if user_cred.login.is_empty() || user_cred.pass.is_empty() {
        return Err(JsValue::from("Credentials must not be empty"));
    }

    if user_cred.login.len() < 8 {
        return Err(JsValue::from("Credentials too short"));
    }

    // create file key (randomly generated strings)
    let fk = write_key_file()?;

    // create salt & pepper to offer variability to password
    let hash = hash_password(&user_cred.pass, &user_cred.login, &fk)?;

    // create db (simple control file)
    create_ctrl_file(hash)?;
    return Ok(true);
}

/// Creates a control file to check password authenticity.
fn create_ctrl_file(mk: ArgonHash) -> Result<(), KeyringError> {
    // create an iv (aes is a block cipher)
    let iv = write_iv_file("")?;

    let ciphered = sym_encrypt(CONTROL_FILE_CONTENT, &mk, &iv)?;

    // creates the effective control file (ciphered with master key)
    return write_ctrl_file(&ciphered);
}

/// Returns true if the credentials match the database.
#[wasm_bindgen]
pub fn sign_in(user_cred: Cred) -> Result<bool, JsValue> {
    if !check_db_exists() {
        panic!("No database");
    }

    return Ok(check_login(user_cred).is_ok());
}

/// Returns the master key if it deciphers the control file
fn check_login(user_cred: Cred) -> Result<ArgonHash, KeyringError> {
    let iv = read_iv_file("")?;
    let fk = read_key_file()?;

    let mk = hash_password(&user_cred.pass, &user_cred.login, &fk)?;

    let cleared = sym_decrypt(&read_ctrl_file()?, &mk, &iv)?;
    let is_correct = cleared.eq(&CONTROL_FILE_CONTENT);

    return match is_correct {
        true => Ok(mk),
        false => return Err(KeyringError::from("Incorrect password")),
    };
}

#[wasm_bindgen]
pub fn obtain_cred(user_cred: Cred, cred_name: &str) -> Result<String, JsValue> {
    if !check_cred_file_exists(cred_name) {
        return Err(JsValue::from("No credential saved with this name"));
    }
    if !check_db_exists() {
        return Err(JsValue::from("No password database exists"));
    }

    let mk = check_login(user_cred)?;
    let cred_iv = read_iv_file(&cred_name)?;

    // read ciphered text
    let ciphertext = read_cred_file(cred_name).map_err(|e| {
        JsValue::from(format!(
            "{} {}: {}",
            e.kind, "Credential could not be read", e.message
        ))
    })?;

    // creates in-place buffer for the cipher
    let cleared = sym_decrypt(&ciphertext, &mk, &cred_iv).map_err(|e| {
        JsValue::from(format!(
            "{} {}: {}",
            e.kind, "Credential could not be read", e.message
        ))
    })?;

    return Ok(String::from_utf8(cleared)
        .map_err(|e| JsValue::from(format!("UTF8 Error: {}", e.to_string())))?);
}

/// Encrypts given credentials.
#[wasm_bindgen]
pub fn create_cred(user_cred: Cred, target_cred: Cred) -> Result<bool, JsValue> {
    if target_cred.login.is_empty() || target_cred.pass.is_empty() {
        return Err(JsValue::from("Credentials must not be empty"));
    }

    if target_cred.login.len() < 8 {
        return Err(JsValue::from("Credentials too short"));
    }

    let mk = check_login(user_cred)?;

    let cred_iv = write_iv_file(&target_cred.login)?;

    let ciphered = sym_encrypt(&target_cred.pass.as_bytes(), &mk, &cred_iv)?;

    write_cred_file(&target_cred.login, &ciphered)?;
    return Ok(true);
}
