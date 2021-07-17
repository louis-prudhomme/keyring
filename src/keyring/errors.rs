use block_modes::BlockModeError as BMError;
use block_modes::InvalidKeyIvLength as IvError;
use serde_json::error::Error as SerdeError;
use std::io::Error as IoError;
use std::string::FromUtf8Error;
use wasm_bindgen::JsValue;
use argon2::Error as ArgonError;

#[derive(Debug)]
pub struct KeyringError {
    kind: String,
    message: String,
}

impl From<IoError> for KeyringError {
    fn from(e: IoError) -> Self {
        return KeyringError {
            kind: "IO".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<&str> for KeyringError {
    fn from(e: &str) -> Self {
        return KeyringError {
            kind: "Manual".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<String> for KeyringError {
    fn from(e: String) -> Self {
        return KeyringError::from(&*e);
    }
}

impl From<IvError> for KeyringError {
    fn from(e: IvError) -> Self {
        return KeyringError {
            kind: "IV".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<BMError> for KeyringError {
    fn from(e: BMError) -> Self {
        return KeyringError {
            kind: "?".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<FromUtf8Error> for KeyringError {
    fn from(e: FromUtf8Error) -> Self {
        return KeyringError {
            kind: "UTF8 parsing error".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<SerdeError> for KeyringError {
    fn from(e: SerdeError) -> Self {
        return KeyringError {
            kind: "JS parsing error".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<ArgonError> for KeyringError {
    fn from(e: ArgonError) -> Self {
        return KeyringError {
            kind: "Argon Error".to_string(),
            message: e.to_string(),
        };
    }
}

impl From<JsValue> for KeyringError {
    fn from(e: JsValue) -> Self {
        return KeyringError {
            kind: "JS error".to_string(),
            message: e.as_string().unwrap_or("shagged".to_string()),
        };
    }
}

impl Into<JsValue> for KeyringError {
    fn into(self) -> JsValue {
        return JsValue::from(self.message);
    }
}
