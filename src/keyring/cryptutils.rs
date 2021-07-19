use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use crate::keyring::io::js_wrapper::log;
use crate::keyring::utils::times;
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
    )?;

    let mut buf = [0u8; HASH_LENGTH];
    argon.hash_password_into(
        Algorithm::Argon2id,
        password.as_bytes(),
        salt.as_bytes(),
        salt.as_bytes(),
        &mut buf,
    )?;

    return Ok(buf);
}

pub fn sym_encrypt(
    cleartext: &[u8],
    mk: &[u8],
    iv: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), KeyringError> {
    // configure cipher
    let cipher = CipherType::new_from_slices(&mk, &iv)?;

    // creates in-place buffer for the cipher
    let mut buf = Vec::new(); //todo might overflow ?

    buf.resize(times(cleartext.len(), BLOCK_SIZE) * BLOCK_SIZE, 0);
    buf[..cleartext.len()].copy_from_slice(cleartext);

    // cipher password
    let ciphered = cipher
        .encrypt(&mut buf, cleartext.len())
        .map_err(|e| KeyringError::from(e))
        .map(|arr| arr.to_vec())?;

    out.resize(ciphered.len(), 0);
    return Ok(out.copy_from_slice(&ciphered));
}

pub fn sym_decrypt(
    ciphertext: &[u8],
    mk: &[u8],
    iv: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), KeyringError> {
    // configure cipher
    let cipher = CipherType::new_from_slices(mk, iv)?;

    // creates in-place buffer for the cipher
    let mut buf = Vec::new();

    buf.resize(times(ciphertext.len(), BLOCK_SIZE) * BLOCK_SIZE, 0);
    buf[..ciphertext.len()].copy_from_slice(ciphertext);

    let deciphered = cipher.decrypt(&mut buf).map(|arr| arr.to_vec())?;
    out.resize(deciphered.len(), 0);

    return Ok(out.copy_from_slice(&deciphered));
}
