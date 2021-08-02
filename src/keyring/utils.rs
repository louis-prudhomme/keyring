use crate::Ctrl;
use crate::CTRL_LENGTH;
use crate::keyring::constants::Key;
use crate::keyring::constants::IV;
use crate::keyring::constants::IV_LENGTH;
use crate::KEY_LENGTH;
use rand::{thread_rng, RngCore};

//todo create generic fn
pub fn gen_rand_iv() -> IV {
    let mut buf = [0u8; IV_LENGTH];
    thread_rng().fill_bytes(&mut buf);
    return buf;
}

pub fn gen_rand_key() -> Key {
    let mut buf = [0u8; KEY_LENGTH];
    thread_rng().fill_bytes(&mut buf);
    return buf;
}

pub fn gen_rand_ctrl() -> Ctrl {
    let mut buf = [0u8; CTRL_LENGTH];
    thread_rng().fill_bytes(&mut buf);
    return buf;
}
