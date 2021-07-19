use crate::keyring::constants::Key;
use crate::keyring::constants::IV;
use crate::keyring::constants::IV_LENGTH;
use crate::KEY_LENGTH;
use rand::{thread_rng, RngCore};

macro_rules! either {
    ($test:expr => $true_expr:expr; $false_expr:expr) => {
        if $test {
            $true_expr
        } else {
            $false_expr
        }
    };
}

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

pub fn times(n: usize, m: usize) -> usize {
    let div = n / m;
    return div + either!(n % m == 0 => 0 ; 1);
}
