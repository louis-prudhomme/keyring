// The wasm-pack uses wasm-bindgen to build and generate JavaScript binding file.
// Import the wasm-bindgen crate.
use wasm_bindgen::prelude::*;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use argon2::{self, Config};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use std::fs::File;
use std::io::prelude::*;

#[macro_use]
extern crate serde_derive;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const CONTROL_FILE_NAME : &str = ".control";
const CONTROL_FILE_CONTENT: &str = "control";

const KEY_FILE_NAME: &str = ".key";
const KEY_LENGTH: usize = 256;
const IV_FILE_EXT: &str = ".iv";
const IV_LENGTH: usize = 32;
const CRED_FILE_EXT: &str = ".cred";

#[wasm_bindgen]
pub fn check_db_exists() -> bool {
  return check_file_exists(CONTROL_FILE_NAME);
}

fn check_file_exists(filename: &str) -> bool {
  return std::path::Path
    ::new(filename)
    .exists();
}

fn check_cred_file_exists(cred_name: &str) -> bool {
  let mut path = String::new();
  path.push_str(cred_name);
  path.push_str(CRED_FILE_EXT);

  return check_file_exists(&path);
}

fn create_file_w_contents(filename: &str, content: &str) -> bool {
  return match File::create(filename)
  .map(|mut file| file
    .write_all(content
      .as_bytes())) {
    Ok(v) => v.is_ok(),
    Err(_) => false
  };
}

fn create_cred_file(cred_name: &str, content: &str) -> bool {
  let mut path = String::new();
  path.push_str(cred_name);
  path.push_str(CRED_FILE_EXT);

  return create_file_w_contents(&path, content);
}

fn create_key_file() -> bool {
  return create_file_w_contents(KEY_FILE_NAME, &gen_rand_string(KEY_LENGTH));
}

fn create_iv_file(filename: &str) -> Option<String> {
  let mut path = String::new();
  path.push_str(filename);
  path.push_str(IV_FILE_EXT);

  let iv = gen_rand_string(IV_LENGTH);

  return match create_file_w_contents(&path, &iv) {
    true => Some(iv),
    false => None
  };
}

fn read_key_file() -> Option<String> {
  return read_file_to_string(KEY_FILE_NAME);
}

fn read_ctrl_file() -> Option<String> {
  return read_file_to_string(CONTROL_FILE_NAME);
}

fn read_iv_file(filename: &str) -> Option<String> {
  let mut path = String::new();
  path.push_str(filename);
  path.push_str(IV_FILE_EXT);

  return read_file_to_string(&path);
}

fn read_cred_file(cred_name: &str) -> Option<String> {
  let mut path = String::new();
  path.push_str(cred_name);
  path.push_str(CRED_FILE_EXT);

  return read_file_to_string(&path);
}

fn read_file_to_string(path: &str) -> Option<String> {
  let mut res = String::new();
  return match File::open(path)
    .map(|mut file| file
    .read_to_string(&mut res)) {
      Ok(_) => Some(res),
      Err(_) => None
    }
}

#[wasm_bindgen]
pub fn signup(raw_user_cred: &JsValue) -> bool {
  // if db exist, then error
  if !check_db_exists() { return false; }

  let user_cred : Cred = match raw_user_cred
      .into_serde() {
    Ok(v) => v,
    Err(_) => return false
  };
  
  // create file key  + salt (randomly generated strings)
  if !create_key_file() { return false; }
  
  // fetch file key
  let fk = match read_key_file() {
    Some(v) => v,
    None => return false
  };
  
  // create salt & pepper to offer variability to password
  let hash = hash_password(&user_cred.pass,
                           &user_cred.login,
                           &fk);

  // create db (simple control file)
  return match create_ctrl_file(hash) {
    Ok(_) => true,
    Err(_) => false
  };
}

fn hash_password(password: &str, salt: &str, pepper: &str) -> String {
  let mut config = Config::default();
  config.secret = pepper.as_bytes();
  // hashes the password to obtain derivation key
  return argon2::hash_encoded(password.as_bytes(),
                              salt.as_bytes(),
                              &config)
      .unwrap();
}

// creates a control file to check password authenticity
fn create_ctrl_file(mk : String) -> Result<(), ()> {
  // create an iv (aes is a block cipher)
  let iv = match create_iv_file("") {
    Some(v) => v,
    None => return Err(())
  };

  // configure cipher
  let cipher = match Aes256Cbc::new_from_slices(
    mk.as_bytes(),
    iv.as_bytes()) {
    Ok(v) => v,
    Err(_) => return Err(())
  };
  
  // creates in-place buffer for the cipher
  let mut buf = [0u8; 4096];
  buf[..CONTROL_FILE_CONTENT.len()]
    .copy_from_slice(CONTROL_FILE_CONTENT
      .as_bytes());

  // cipher password
  let ciphered = String::from_utf8(cipher
      .encrypt(&mut buf, CONTROL_FILE_CONTENT.len())
      .map(|ciphered| ciphered.to_vec())
      .unwrap_or(Vec::new()))
      .unwrap_or(String::new());

  // creates the effective control file (ciphered with master key)
  return match create_file_w_contents(CONTROL_FILE_NAME, &ciphered) {
    true => Ok(()),
    false => Err(())
  }
}

fn gen_rand_string(length: usize) -> String {
  return thread_rng()
    .sample_iter(&Alphanumeric)
    .take(length)
    .map(char::from)
    .collect();
}

#[wasm_bindgen]
pub fn sign_in(raw_user_cred: &JsValue) -> Option<bool> {
  let user_cred = raw_user_cred
      .into_serde()
      .unwrap();
  if !check_db_exists() { return Some(false); }

  return Some(check_login(user_cred).is_some());
}

/// Returns the master key if it deciphers the control file
fn check_login(user_cred: Cred) -> Option<String> {
  let iv = match read_iv_file("") {
    Some(v) => v,
    None => return None
  };
  let fk = match read_key_file() {
    Some(v) => v,
    None => return None
  };

  let mk = hash_password(&user_cred.pass, &user_cred.login, &fk);

  // configure cipher
  let cipher = match Aes256Cbc::new_from_slices(mk.as_bytes(), iv.as_bytes()) {
    Ok(v) => v,
    Err(_) => return None
  };

  // read ciphered text
  let ciphertext = match read_ctrl_file() {
    Some(v) => v,
    None => return None
  };

  // creates in-place buffer for the cipher
  let mut buf = [0u8; 4096];
  buf[..ciphertext.len()]
    .copy_from_slice(ciphertext
      .as_bytes());

  let is_correct = cipher.decrypt(&mut buf)
      .map(|clear| clear.to_vec())
      .map(|clear| clear.eq(CONTROL_FILE_CONTENT
        .as_bytes()))
      .unwrap_or(false);

  return match is_correct {
    true => Some(mk),
    false => None
  };
}

#[wasm_bindgen]
pub fn obtain_cred(raw_user_cred: JsValue,
                   cred_name: &str) -> JsValue {

  if !check_cred_file_exists(cred_name) { return JsValue::NULL; }
  if !check_db_exists() { return JsValue::NULL; }

  let user_cred : Cred = match raw_user_cred
      .into_serde() {
    Ok(v) => v,
    Err(_) => return JsValue::NULL
  };
  let mk = match check_login(user_cred) {
    Some(v) => v,
    None => return JsValue::NULL
  };
  let cred_iv = match read_iv_file(&cred_name) {
    Some(v) => v,
    None => return JsValue::NULL
  };

  // configure cipher
  let cipher = match Aes256Cbc::new_from_slices(mk.as_bytes(), cred_iv.as_bytes()) {
    Ok(v) => v,
    Err(_) => return JsValue::NULL
  };

  // read ciphered text
  let ciphertext = match read_cred_file(cred_name) {
    Some(v) => v,
    None => return JsValue::NULL
  };

  // creates in-place buffer for the cipher
  let mut buf = [0u8; 4096];
  buf[..ciphertext.len()]
      .copy_from_slice(ciphertext
          .as_bytes());

  let result_cred = match cipher.decrypt(&mut buf)
      .map(|clear | clear.to_vec())
      .map(|clear | String::from_utf8(clear)) {
    Ok(v) => match v {
      Ok(w) => Cred {
        login: cred_name.to_string(),
        pass: w.to_string() },
      Err(_) => return JsValue::NULL
    },
    Err(_) => return JsValue::NULL
  };

  return match JsValue::from_serde(&result_cred) {
    Ok(v) => v,
    Err(_) => JsValue::NULL
  };
}

#[wasm_bindgen]
pub fn create_cred(raw_user_cred: &JsValue,
                   raw_target_cred: &JsValue) -> bool {
  let user_cred : Cred = match raw_user_cred
      .into_serde() {
    Ok(v) => v,
    Err(_) => return false
  };
  let target_cred : Cred = match raw_target_cred
      .into_serde() {
    Ok(v) => v,
    Err(_) => return false
  };
  let mk = match check_login(user_cred) {
    Some(v) => v,
    None => return false
  };
  let cred_iv = match create_iv_file(&target_cred.login) {
    Some(v) => v,
    None => return false
  };

  // configure cipher
  let cipher = match Aes256Cbc::new_from_slices(
    mk.as_bytes(),
    cred_iv.as_bytes()) {
    Ok(v) => v,
    Err(_) => return false
  };

  let mut buf = [0u8; 4096];
  buf[..target_cred.pass.len()]
    .copy_from_slice(target_cred.pass
      .as_bytes());

  let ciphered = String::from_utf8(cipher
    .encrypt(&mut buf, target_cred.pass.len())
    .map(|ciphered| ciphered.to_vec())
    .unwrap_or(Vec::new()))
    .unwrap_or(String::new());

  return create_cred_file(&target_cred.login, &ciphered);
}

#[derive(Serialize, Deserialize)]
struct Cred {
  login: String,
  pass : String,
}