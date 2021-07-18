use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::u8_arr_to_string;
use argon2::{Algorithm, Argon2, Params};
use block_modes::BlockMode;

pub fn hash_password(password: &str, salt: &str, pepper: &[u8]) -> Result<ArgonHash, KeyringError> {
    let params = Params::default();
    let argon = Argon2::new(
        Option::Some(pepper),
        params.t_cost,
        params.m_cost,
        params.p_cost,
        params.version,
    );

    let mut buf = [0u8; HASH_LENGTH];
    argon?.hash_password_into(
        Algorithm::Argon2id,
        password.as_bytes(),
        salt.as_bytes(),
        salt.as_bytes(),
        &mut buf,
    )?;

    return Ok(buf);
}

pub fn sym_encrypt(clear: &str, mk: &[u8], iv: &[u8]) -> Result<String, KeyringError> {
    // configure cipher
    let cipher = CipherType::new_from_slices(&mk, &iv)?;

    // creates in-place buffer for the cipher
    let mut buf = [0u8; 4096]; //todo
    buf[..clear.len()].copy_from_slice(clear.as_bytes());

    // cipher password
    let ciphered = cipher
        .encrypt(&mut buf, clear.len())
        .map_err(|e| KeyringError::from(e))
        .map(|arr| u8_arr_to_string(arr))?;

    return Ok(ciphered);
}

pub fn sym_decrypt(ciphertext: &str, mk: &[u8], iv: &[u8]) -> Result<String, KeyringError> {
    // configure cipher
    let cipher = CipherType::new_from_slices(mk, iv)?;

    // creates in-place buffer for the cipher
    let mut buf = [0u8; 4096];
    buf[..ciphertext.len()].copy_from_slice(ciphertext.as_bytes());

    let deciphered = cipher.decrypt(&mut buf).map(|arr| u8_arr_to_string(arr))?;

    return Ok(deciphered);
}
