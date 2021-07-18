// The wasm-pack uses wasm-bindgen to build and generate JavaScript binding file.
// Import the wasm-bindgen crate.
use crate::keyring::cryptutils::{hash_password, sym_decrypt, sym_encrypt};
use crate::keyring::constants::*;
use crate::keyring::utils::u8_arr_to_string;

use wasm_bindgen::prelude::*;
mod keyring;


use crate::keyring::errors::*;
use crate::keyring::io::read::*;
use crate::keyring::io::write::*;
use crate::keyring::utils::Cred;
use std::panic;

#[macro_use]
extern crate serde_derive;

#[wasm_bindgen]
pub fn check_db_exists() -> bool {
    console_error_panic_hook::set_once();
    return check_db_file_exists();
}

#[wasm_bindgen]
pub fn sign_up(user_cred: Cred) -> Result<bool, JsValue> {
    // if db exist, then error
    if check_db_exists() {
        panic!("Database already exists");
    }

    // create file key (randomly generated strings)
    let fk = write_key_file().expect("");

    // create salt & pepper to offer variability to password
    let hash = hash_password(&user_cred.pass, &user_cred.login, &fk).expect("");

    // create db (simple control file)
    create_ctrl_file(hash).expect("");

    return Ok(true);
}

// creates a control file to check password authenticity
fn create_ctrl_file(mk: ArgonHash) -> Result<(), KeyringError> {
    // create an iv (aes is a block cipher)
    let iv = write_iv_file("")?;

    let ciphered = sym_encrypt(CONTROL_FILE_CONTENT, &mk, &iv)?;

    // creates the effective control file (ciphered with master key)
    return write_ctrl_file(&ciphered);
}

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

    let mk = hash_password(&user_cred.pass, &user_cred.login, &fk.as_bytes())?;

    let cleared = sym_decrypt(&read_ctrl_file()?, &mk, &iv.as_bytes())?;
    let is_correct = cleared.eq(CONTROL_FILE_CONTENT);

    return match is_correct {
        true => Ok(mk),
        false => return Err(KeyringError::from("Incorrect password")),
    };
}

#[wasm_bindgen]
pub fn obtain_cred(user_cred: Cred, cred_name: &str) -> Result<Cred, JsValue> {
    if !check_cred_file_exists(cred_name) {
        panic!("No credential saved with this name");
    }
    if !check_db_exists() {
        panic!("No password database exists");
    }
    let mk = check_login(user_cred).expect("");
    let cred_iv = read_iv_file(&cred_name).expect("");

    // read ciphered text
    let ciphertext = read_cred_file(cred_name).expect("");

    // creates in-place buffer for the cipher
    let cleared = sym_decrypt(&ciphertext, &mk, &cred_iv.as_bytes()).expect("");
    return Ok(Cred {
        login: cred_name.to_string(),
        pass: cleared.to_string(),
    });
}

#[wasm_bindgen]
pub fn create_cred(user_cred: Cred, target_cred: Cred) -> Result<bool, JsValue> {
    let mk = check_login(user_cred).expect("");
    let cred_iv = write_iv_file(&target_cred.login).expect("");

    let ciphered = sym_encrypt(&target_cred.pass, &mk, &cred_iv).expect("");

    write_cred_file(&target_cred.login, &ciphered)
        .expect("");
    return Ok(true);
}
