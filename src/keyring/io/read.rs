use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::keyring::io::js_wrapper::{check_info_exists_in_js, read_from_js};

pub fn check_db_file_exists() -> bool {
    return check_file_exists(CONTROL_FILE_NAME);
}

fn check_file_exists(filename: &str) -> bool {
    return check_info_exists_in_js(filename);
}

pub fn check_cred_file_exists(cred_name: &str) -> bool {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return check_file_exists(&path);
}

pub fn read_key_file() -> Result<Vec<u8>, KeyringError> {
    return read_file_to_string(KEY_FILE_NAME);
}

pub fn read_ctrl_file() -> Result<Vec<u8>, KeyringError> {
    return read_file_to_string(CONTROL_FILE_NAME);
}

pub fn read_iv_file(filename: &str) -> Result<Vec<u8>, KeyringError> {
    let mut path = String::new();
    path.push_str(filename);
    path.push_str(IV_FILE_EXT);

    return read_file_to_string(&path);
}

pub fn read_cred_file(cred_name: &str) -> Result<Vec<u8>, KeyringError> {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return read_file_to_string(&path);
}

fn read_file_to_string(path: &str) -> Result<Vec<u8>, KeyringError> {
    return read_from_js(path).map_err(|e| KeyringError::from(e));
}
