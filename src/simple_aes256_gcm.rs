use aes_gcm::Aes256Gcm;
use aead::{Aead, NewAead, generic_array::GenericArray};
use std::{fmt, error};
use std::convert::{TryInto, TryFrom};

#[derive(Debug, Clone)]
pub struct InvalidKeySizeError;

impl fmt::Display for InvalidKeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "Please provide a 32-byte key")
    }
}

impl error::Error for InvalidKeySizeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

pub struct Key {
    pub u8_array: [u8; 32]
}

impl TryFrom<&str> for Key {
    type Error = InvalidKeySizeError;
    fn try_from(key: &str) -> Result<Self, InvalidKeySizeError> {
        let u8_array: Result<[u8; 32], _> = key.as_bytes().try_into();
        match u8_array {
            Ok(value) => Ok(Self {
                u8_array: value
            }),
            Err(_) => Err(InvalidKeySizeError)
        }
    }
}

#[derive(Debug, Clone)]
pub enum InvalidIvError {
    InvalidIvSizeError,
    InvalidIvBase64Error
}


impl fmt::Display for InvalidIvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InvalidIvError::InvalidIvSizeError => write!(f, "{}", "Please provide a 12-byte, base64-encoded, iv"),
            InvalidIvError::InvalidIvBase64Error => write!(f, "{}", "Please provide a valid base64"),
        }
    }
}

impl error::Error for InvalidIvError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

pub struct Iv {
    pub u8_array: [u8; 12]
}

impl TryFrom<&str> for Iv {
    type Error = InvalidIvError;
    fn try_from(base64_iv: &str) -> Result<Iv, InvalidIvError> {
        let encrypted_value = match base64::decode(base64_iv) {
            Ok(data) => data,
            Err(_) => return Err(InvalidIvError::InvalidIvBase64Error)
        };

        let u8_array: Result<[u8; 12], _> = encrypted_value.as_slice().try_into();
        match u8_array {
            Ok(value) => Ok(Iv {
                u8_array: value
            }),
            Err(_) => Err(InvalidIvError::InvalidIvSizeError)
        }
    }
}
impl Iv {
    pub fn generate() -> Iv {
        Iv {
            u8_array: rand::random::<[u8; 12]>()
        }
    }
}

impl fmt::Display for Iv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.u8_array))
    }
}

pub struct Encrypted {
    pub u8_vec: Vec<u8>
}

impl TryFrom<&str> for Encrypted {
    type Error = base64::DecodeError;
    fn try_from(base64_encrypted: &str) -> Result<Encrypted, base64::DecodeError> {
        Ok(Encrypted {
            u8_vec: base64::decode(base64_encrypted)?
        })
    }
}

impl fmt::Display for Encrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.u8_vec))
    }
}

pub struct EncryptedValueAndId {
    pub encrypted: Encrypted,
    pub iv: Iv
}

pub fn encrypt<'a>(key: &Key, value: &'a [u8]) -> Result<EncryptedValueAndId, &'static str> {
    let iv = Iv::generate();
    let nonce = GenericArray::from_slice(&iv.u8_array);
    let client = Aes256Gcm::new(GenericArray::clone_from_slice(&key.u8_array));
    match client.encrypt(nonce, value) {
        Ok(ciphertext) => Ok(EncryptedValueAndId {
            iv: iv,
            encrypted: Encrypted {
                u8_vec: ciphertext
            }
        }),
        Err(_) => Err("encryption failure!")
    }
}

pub fn decrypt(key: &Key, encrypted_value_and_iv: EncryptedValueAndId) -> Result<String, &'static str> {
    let nonce = GenericArray::from_slice(&encrypted_value_and_iv.iv.u8_array);
    let client = Aes256Gcm::new(GenericArray::clone_from_slice(&key.u8_array));

    match client.decrypt(nonce, encrypted_value_and_iv.encrypted.u8_vec.as_ref()) {
        Ok(decrypted_u8_vec) => match String::from_utf8(decrypted_u8_vec) {
            Ok(decrypted_string) => Ok(decrypted_string),
            Err(_) => Err("Invalid UTF-8")
        },
        Err(_) => Err("Decryption error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_new_3_bytes_fails() {
        match Key::try_from("012") {
            Ok(_) => assert!(false),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn key_new_33_bytes_fails() {
        match Key::try_from("012345678901234567890123456789012") {
            Ok(_) => assert!(false),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn key_new_32_bytes_succeeds() {
        match Key::try_from("01234567890123456789012345678901") {
            Ok(key) => assert_eq!(key.u8_array, [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49]),
            Err(_) => assert!(false, "Should succeed")
        }
    }

    #[test]
    fn iv_try_from_invalid_base64_fails() {
        match Iv::try_from("012") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvBase64Error => assert!(true),
                _ => assert!(false, "Should err an InvalidIvError::InvalidIvBase64Error")
            }
        }
    }

    #[test]
    fn iv_try_from_valid_3byte_fails() {
        match Iv::try_from("YWJj") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvSizeError => assert!(true),
                _ => assert!(false, "Should err an InvalidIvError::InvalidIvSizeError")
            }
        }
    }

    #[test]
    fn iv_try_from_valid_13byte_fails() {
        match Iv::try_from("MDEyMzQ1Njc4OTAxMg==") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvSizeError => assert!(true),
                _ => assert!(false, "Should err an InvalidIvError::InvalidIvSizeError")
            }
        }
    }

    #[test]
    fn iv_try_from_valid_12byte_succeeds() {
        match Iv::try_from("MDEyMzQ1Njc4OTAx") {
            Ok(iv) => assert_eq!(iv.u8_array, [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49]),
            Err(_) => assert!(false, "Should succeeds")
        }
    }

    #[test]
    fn iv_generate() {
        assert!(
            Iv::generate().u8_array != Iv::generate().u8_array,
            "Should generate almost unique values"
        )
    }

    #[test]
    fn iv_format() {
        assert_eq!(
            format!("{}", Iv::try_from("MDEyMzQ1Njc4OTAx").unwrap()),
            "MDEyMzQ1Njc4OTAx"
        )
    }

    #[test]
    fn encrypted_from64_invalid_base64() {
        match Encrypted::try_from("aaaaaaa") {
            Ok(_) => assert!(false, "Should err"),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn encrypted_from64_valid_base64() {
        match Encrypted::try_from("YWFhYWFhYQ==") {
            Ok(encryped) => assert_eq!(encryped.u8_vec, vec![97, 97, 97, 97, 97, 97, 97]),
            Err(_) => assert!(false, "Should ok")
        }
    }

    #[test]
    fn encrypted_format() {
        assert_eq!(
            format!("{}", Encrypted::try_from("YWFhYWFhYQ==").unwrap()),
            "YWFhYWFhYQ=="
        )
    }
}
