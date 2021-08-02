// iv len = 32, key len = 64
pub type IV = [u8; IV_LENGTH];
pub type Key = [u8; KEY_LENGTH];
pub type Ctrl = [u8; CTRL_LENGTH];
pub type ArgonHash = [u8; HASH_LENGTH];

pub const IV_LENGTH: usize = 12; //not exactly an iv
pub const CTRL_LENGTH: usize = 512;
pub const KEY_LENGTH: usize = 256;
pub const HASH_LENGTH: usize = 32;

pub const CONTROL_FILE_NAME: &str = ".control";
pub const KEY_FILE_NAME: &str = ".key";
pub const IV_FILE_EXT: &str = ".iv";
pub const CRED_FILE_EXT: &str = ".cred";
