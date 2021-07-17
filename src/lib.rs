// The wasm-pack uses wasm-bindgen to build and generate JavaScript binding file.
// Import the wasm-bindgen crate.
use crate::keyring::constants::Aes256Cbc;
use crate::keyring::constants::CONTROL_FILE_CONTENT;
use wasm_bindgen::prelude::*;

mod keyring;

use argon2::{self, Config};
use block_modes::BlockMode;

use crate::keyring::errors::*;
use crate::keyring::io::read::*;
use crate::keyring::io::write::*;
use crate::keyring::utils::Cred;


#[macro_use]
extern crate serde_derive;

#[wasm_bindgen]
pub fn check_db_exists() -> bool {
    return check_db_file_exists(); 
}

#[wasm_bindgen]
pub fn sign_up(user_cred: Cred) -> Result<bool, JsValue> {
    // if db exist, then error
    if check_db_exists() {
        panic!("Database already exists");
    }

    // create file key  + salt (randomly generated strings)
    let fk = write_key_file().expect("");

    // create salt & pepper to offer variability to password
    let hash = hash_password(&user_cred.pass, &user_cred.login, &fk);

    // create db (simple control file)
    create_ctrl_file(hash).expect("");
    return Ok(true);
}

fn hash_password(password: &str, salt: &str, pepper: &str) -> String {
    let mut config = Config::default();
    config.secret = pepper.as_bytes();
    // hashes the password to obtain derivation key
    return argon2::hash_encoded(password.as_bytes(), salt.as_bytes(), &config)
    .unwrap();//todo
}

// creates a control file to check password authenticity
fn create_ctrl_file(mk: String) -> Result<(), KeyringError> {
    // create an iv (aes is a block cipher)
    let iv = write_iv_file("")?;

    // configure cipher
    let cipher = Aes256Cbc::new_from_slices(mk.as_bytes(), iv.as_bytes())?;

    // creates in-place buffer for the cipher
    let mut buf = [0u8; 4096];
    buf[..CONTROL_FILE_CONTENT.len()].copy_from_slice(CONTROL_FILE_CONTENT.as_bytes());

    // cipher password
    let ciphered = String::from_utf8(
        cipher
            .encrypt(&mut buf, CONTROL_FILE_CONTENT.len())
            .map(|ciphered| ciphered.to_vec())
            .unwrap_or(Vec::new()),
    )
    .unwrap_or(String::new());

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
fn check_login(user_cred: Cred) -> Result<String, KeyringError> {
    let iv = read_iv_file("")?;
    let fk = read_key_file()?;

    let mk = hash_password(&user_cred.pass, &user_cred.login, &fk);

    // configure cipher
    let cipher = Aes256Cbc::new_from_slices(mk.as_bytes(), iv.as_bytes())?;

    // read ciphered text
    let ciphertext = read_ctrl_file()?;

    // creates in-place buffer for the cipher
    let mut buf = [0u8; 4096];
    buf[..ciphertext.len()].copy_from_slice(ciphertext.as_bytes());

    let is_correct = cipher
        .decrypt(&mut buf)
        .map(|clear| clear.to_vec())
        .map(|clear| clear.eq(CONTROL_FILE_CONTENT.as_bytes()))
        .unwrap_or(false);

    return match is_correct {
        true => Ok(mk),
        false => return Err(KeyringError::from("Password incorrect")),
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

    // configure cipher
    let cipher = Aes256Cbc::new_from_slices(mk.as_bytes(), cred_iv.as_bytes()).expect("");

    // read ciphered text
    let ciphertext = read_cred_file(cred_name).expect("");

    // creates in-place buffer for the cipher
    let mut buf = [0u8; 4096];
    buf[..ciphertext.len()].copy_from_slice(ciphertext.as_bytes());

    // decipher credentials
    let result_cred = cipher
        .decrypt(&mut buf)
        .map(|clear| clear.to_vec())
        .map(|clear| String::from_utf8(clear)).expect("").expect("");

    return Ok(Cred {
        login: cred_name.to_string(),
        pass: result_cred.to_string(),
    });
}

#[wasm_bindgen]
pub fn create_cred(user_cred: Cred, target_cred: Cred) -> Result<bool, JsValue> {
    let mk = check_login(user_cred).expect("");
    let cred_iv = write_iv_file(&target_cred.login).expect("");

    // configure cipher
    let cipher = Aes256Cbc::new_from_slices(mk.as_bytes(), cred_iv.as_bytes()).expect("");

    let mut buf = [0u8; 4096];
    buf[..target_cred.pass.len()].copy_from_slice(target_cred.pass.as_bytes());

    let ciphered = String::from_utf8(
        cipher
            .encrypt(&mut buf, target_cred.pass.len())
            .map(|ciphered| ciphered.to_vec())
            .unwrap_or(Vec::new()),
    )
    .unwrap_or(String::new());

    write_cred_file(&target_cred.login, &ciphered).expect("");
    return Ok(true);
}
