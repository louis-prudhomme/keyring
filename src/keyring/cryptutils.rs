use crate::keyring::constants::*;
use crate::keyring::errors::KeyringError;
use argon2::{Algorithm, Argon2, Params};
use sha3::{Digest, Sha3_256};

use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};

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
        &hash(salt.as_bytes())?,
        &hash(salt.as_bytes())?,
        &mut buf,
    )?;

    return Ok(buf);
}

pub fn sym_encrypt(
    cleartext: &[u8],
    mk: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, KeyringError> {
    // configure cipher
    let key = Key::from_slice(mk);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(iv);

    let ciphered = cipher.encrypt(nonce, cleartext.as_ref())?;

    return Ok(ciphered);
}

pub fn sym_decrypt(
    ciphertext: &[u8],
    mk: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, KeyringError> {
    // configure cipher
    let key = Key::from_slice(mk);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(iv);

    
    let cleared = cipher.decrypt(nonce, ciphertext)?;

    return Ok(cleared);
}

pub fn hash(
    cleartext: &[u8]
) -> Result<Vec<u8>, KeyringError> {
    let mut hasher = Sha3_256::new();
    hasher.update(cleartext);
    return Ok(hasher.finalize().to_vec());
}