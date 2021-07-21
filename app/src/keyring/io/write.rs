use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::keyring::io::js_wrapper::write_to_js;
use crate::keyring::utils::*;

fn write_w_contents(filename: &str, content: &[u8]) -> Result<(), KeyringError> {
    return write_to_js(filename, content).map_err(|e| KeyringError::from(e));
}

pub fn write_cred(cred_name: &str, content: &[u8]) -> Result<(), KeyringError> {
    return write_w_contents(&format!("{}{}", cred_name, CRED_FILE_EXT), content);
}

pub fn write_key() -> Result<Key, KeyringError> {
    let key = gen_rand_key();

    write_w_contents(KEY_FILE_NAME, &key)?;
    return Ok(key);
}

pub fn write_ctrl(content: &[u8]) -> Result<(), KeyringError> {
    return write_w_contents(CONTROL_FILE_NAME, content);
}

pub fn write_iv(filename: &str) -> Result<IV, KeyringError> {
    let iv = gen_rand_iv();

    write_w_contents(&format!("{}{}", filename, IV_FILE_EXT), &iv)?;
    return Ok(iv);
}
