use block_modes::BlockModeError as BMError;
use block_modes::InvalidKeyIvLength as IvError;
use wasm_bindgen::JsValue;
use std::io::Error as IoError;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub struct KeyringError {
    kind: String,
    message: String,
}

impl From<IoError> for KeyringError {
    fn from(e: IoError) -> Self {
        return KeyringError {
            kind: "io".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<&str> for KeyringError {
    fn from(e: &str) -> Self {
        return KeyringError {
            kind: "manual".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<IvError> for KeyringError {
    fn from(e: IvError) -> Self {
        return KeyringError {
            kind: "invalid_iv".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<BMError> for KeyringError {
    fn from(e: BMError) -> Self {
        return KeyringError {
            kind: "invalid_iv".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<FromUtf8Error> for KeyringError {
    fn from(e: FromUtf8Error) -> Self {
        return KeyringError {
            kind: "invalid_iv".to_string(),
            message: e.to_string(),
        };
    }
}

impl Into<JsValue> for KeyringError {
    fn into(self) -> JsValue {
        return JsValue::from(self.message);
    }
}
