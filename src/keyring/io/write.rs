use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::keyring::utils::gen_rand_string;
use std::fs;

fn write_file_w_contents(filename: &str,
                         content: &str) -> Result<(), KeyringError> {
    let mut path = filename.to_string().clone();
    return match fs::write(&mut path, content.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => Err(KeyringError::from(e))
    };
}

pub fn write_cred_file(cred_name: &str,
                       content: &str) -> Result<(), KeyringError> {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return write_file_w_contents(&path, content);
}

pub fn write_key_file() -> Result<String, KeyringError> {
    let key = gen_rand_string(KEY_LENGTH);

    write_file_w_contents(KEY_FILE_NAME, &key)?;
    return Ok(key);
}

pub fn write_ctrl_file(content: &str) -> Result<(), KeyringError> {
    return write_file_w_contents(CONTROL_FILE_NAME,
                                 content);
}

pub fn write_iv_file(filename: &str) -> Result<String, KeyringError> {
    let mut path = String::new();
    path.push_str(filename);
    path.push_str(IV_FILE_EXT);

    let iv = gen_rand_string(IV_LENGTH);

    write_file_w_contents(&path, &iv)?;
    return Ok(iv);
}