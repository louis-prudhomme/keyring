use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::Cbc;

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub const CONTROL_FILE_NAME: &str = ".control";
pub const CONTROL_FILE_CONTENT: &str = "control";

pub const KEY_FILE_NAME: &str = ".key";
pub const KEY_LENGTH: usize = 256;
pub const IV_FILE_EXT: &str = ".iv";
pub const IV_LENGTH: usize = 16;
pub const CRED_FILE_EXT: &str = ".cred";
