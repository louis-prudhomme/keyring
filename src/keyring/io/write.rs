use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::keyring::io::js_wrapper::{ write_to_js};
use crate::keyring::utils::*;

fn write_file_w_contents(filename: &str, content: &[u8]) -> Result<(), KeyringError> {
    let path = filename.to_string().clone();
    return write_to_js(&path, content).map_err(|e| KeyringError::from(e));
}

pub fn write_cred_file(cred_name: &str, content: &[u8]) -> Result<(), KeyringError> {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return write_file_w_contents(&path, content);
}

pub fn write_key_file() -> Result<Key, KeyringError> {
    let key = gen_rand_key();

    write_file_w_contents(KEY_FILE_NAME, &key)?;
    return Ok(key);
}

pub fn write_ctrl_file(content: &[u8]) -> Result<(), KeyringError> {
    return write_file_w_contents(CONTROL_FILE_NAME, content);
}

pub fn write_iv_file(filename: &str) -> Result<IV, KeyringError> {
    let mut path = String::new();
    path.push_str(filename);
    path.push_str(IV_FILE_EXT);

    let iv = gen_rand_iv();

    write_file_w_contents(&path, &iv)?;
    return Ok(iv);
}
