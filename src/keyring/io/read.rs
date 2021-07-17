use crate::keyring::constants::*;
use std::fs::File;
use std::io::Read;
use crate::keyring::errors::KeyringError;

pub fn check_db_file_exists() -> bool {
    return check_file_exists(CONTROL_FILE_NAME);
}

fn check_file_exists(filename: &str) -> bool {
    return std::path::Path
    ::new(filename)
        .exists();
}

pub fn check_cred_file_exists(cred_name: &str) -> bool {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return check_file_exists(&path);
}

pub fn read_key_file() -> Result<String, KeyringError> {
    return read_file_to_string(KEY_FILE_NAME);
}

pub fn read_ctrl_file() -> Result<String, KeyringError> {
    return read_file_to_string(CONTROL_FILE_NAME);
}

pub fn read_iv_file(filename: &str) -> Result<String, KeyringError> {
    let mut path = String::new();
    path.push_str(filename);
    path.push_str(IV_FILE_EXT);

    return read_file_to_string(&path);
}

pub fn read_cred_file(cred_name: &str) -> Result<String, KeyringError> {
    let mut path = String::new();
    path.push_str(cred_name);
    path.push_str(CRED_FILE_EXT);

    return read_file_to_string(&path);
}

fn read_file_to_string(path: &str) -> Result<String, KeyringError> {
    let mut res = String::new();
    return match File::open(path)
        .map(|mut file| file
            .read_to_string(&mut res)) {
        Ok(_) => Ok(res),
        Err(e) => Err(KeyringError::from(e))
    }

}