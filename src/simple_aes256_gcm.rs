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

pub struct Decrypted<'a> {
    value: &'a str
}
impl<'a> From<&'a str> for Decrypted<'a> {
    fn from(value: &'a str) -> Self {
        Self { value: value }
    }
}
impl<'a> fmt::Display for Decrypted<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.value)
    }
}


pub struct EncryptedValueAndId {
    pub encrypted: Encrypted,
    pub iv: Iv
}

pub fn encrypt<'a>(key: &Key, decrypted: &Decrypted) -> Result<EncryptedValueAndId, aead::Error> {
    let iv = Iv::generate();
    let nonce = GenericArray::from_slice(&iv.u8_array);
    let client = Aes256Gcm::new(GenericArray::clone_from_slice(&key.u8_array));
    let ciphertext =  client.encrypt(nonce, decrypted.value.as_bytes())?;
    Ok(EncryptedValueAndId {
        iv: iv,
        encrypted: Encrypted {
            u8_vec: ciphertext
        }
    })
}

#[derive(Debug, Clone)]
pub enum DecryptionError {
    InvalidUTF8DecryptionError,
    GenericDecryptionError
}
impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecryptionError::InvalidUTF8DecryptionError => write!(f, "{}", "Decryption error: invalid UTF-8"),
            DecryptionError::GenericDecryptionError => write!(f, "{}", "Decryption error"),
        }
    }
}

impl error::Error for DecryptionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

pub fn decrypt(key: &Key, encrypted_value_and_iv: EncryptedValueAndId) -> Result<String, DecryptionError> {
    let nonce = GenericArray::from_slice(&encrypted_value_and_iv.iv.u8_array);
    let client = Aes256Gcm::new(GenericArray::clone_from_slice(&key.u8_array));

    match client.decrypt(nonce, encrypted_value_and_iv.encrypted.u8_vec.as_ref()) {
        Ok(decrypted_u8_vec) => match String::from_utf8(decrypted_u8_vec) {
            Ok(decrypted_string) => Ok(decrypted_string),
            Err(_) => Err(DecryptionError::InvalidUTF8DecryptionError)
        },
        Err(_) => Err(DecryptionError::GenericDecryptionError)
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
            Err(_) => assert!(false, "Should succeed"),
            Ok(key) => assert_eq!(key.u8_array, [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49])
        }
    }

    #[test]
    fn iv_try_from_invalid_base64_fails() {
        match Iv::try_from("012") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvSizeError => assert!(false, "Should err an InvalidIvError::InvalidIvBase64Error"),
                InvalidIvError::InvalidIvBase64Error => assert!(true)
            }
        }
    }

    #[test]
    fn iv_try_from_valid_3byte_fails() {
        match Iv::try_from("YWJj") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvBase64Error => assert!(false, "Should err an InvalidIvError::InvalidIvSizeError"),
                InvalidIvError::InvalidIvSizeError => assert!(true)
            }
        }
    }

    #[test]
    fn iv_try_from_valid_13byte_fails() {
        match Iv::try_from("MDEyMzQ1Njc4OTAxMg==") {
            Ok(_) => assert!(false),
            Err(e) => match e {
                InvalidIvError::InvalidIvBase64Error => assert!(false, "Should err an InvalidIvError::InvalidIvSizeError"),
                InvalidIvError::InvalidIvSizeError => assert!(true)
            }
        }
    }

    #[test]
    fn iv_try_from_valid_12byte_succeeds() {
        match Iv::try_from("MDEyMzQ1Njc4OTAx") {
            Err(_) => assert!(false, "Should succeeds"),
            Ok(iv) => assert_eq!(iv.u8_array, [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49])
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
            Err(_) => assert!(false, "Should ok"),
            Ok(encryped) => assert_eq!(encryped.u8_vec, vec![97, 97, 97, 97, 97, 97, 97])
        }
    }

    #[test]
    fn encrypted_format() {
        assert_eq!(
            format!("{}", Encrypted::try_from("YWFhYWFhYQ==").unwrap()),
            "YWFhYWFhYQ=="
        )
    }

    // #[test]
    // Not able to find any example that would make this err...
    // fn encrypt_err_when_encryption_error() {
    //     let key = Key::try_from("12345678901234567890123456789012").unwrap();
    //     let decrypted = Decrypted::from("???")
    //     match encrypt(&key, &decrypted) {
    //         Ok(_) => assert!(false, "Should err"),
    //         Err(e) => assert!(true)
    //     }
    // }

    #[test]
    fn encrypted_values_are_different_for_same_inputs() {
        let encrypted_1 = encrypt(
            &Key::try_from("12345678901234567890123456789012").unwrap(),
            &Decrypted::from("This is a text.")
        ).unwrap();
        let encrypted_2 = encrypt(
            &Key::try_from("12345678901234567890123456789012").unwrap(),
            &Decrypted::from("This is a text.")
        ).unwrap();
        assert!(encrypted_1.encrypted.u8_vec != encrypted_2.encrypted.u8_vec)
    }

    #[test]
    fn encrypted_values_are_different_for_different_inputs() {
        let encrypted_1 = encrypt(
            &Key::try_from("12345678901234567890123456789012").unwrap(),
            &Decrypted::from("This is a text.")
        ).unwrap();
        let encrypted_2 = encrypt(
            &Key::try_from("12345678901234567890123456789012").unwrap(),
            &Decrypted::from("This is another text.")
        ).unwrap();
        assert!(encrypted_1.encrypted.u8_vec != encrypted_2.encrypted.u8_vec)
    }

    #[test]
    fn encrypt_decrypt_is_iso() {
        let key = Key::try_from("12345678901234567890123456789012").unwrap();
        let encrypted = encrypt(
            &key,
            &Decrypted::from("This is a text.")
        ).unwrap();

        assert_eq!(decrypt(&key, encrypted).unwrap(), String::from("This is a text."))
    }

    #[test]
    // TO WRITE
    fn decrypt_fails_when_non_utf8() {
        let key = Key::try_from("12345678901234567890123456789012").unwrap();

        let iv = Iv::generate();
        let nonce = GenericArray::from_slice(&iv.u8_array);
        let client = Aes256Gcm::new(GenericArray::clone_from_slice(&key.u8_array));
        let invalid_utf8_bytes: &[u8] = &[133u8, 133u8];
        let ciphertext = client.encrypt(nonce, invalid_utf8_bytes).unwrap();

        let encrypted_value_and_iv = EncryptedValueAndId {
            iv: iv,
            encrypted: Encrypted {
                u8_vec: ciphertext
            }
        };

        match decrypt(&key, encrypted_value_and_iv) {
            Ok(_) => assert!(false, "Should err InvalidUTF8DecryptionError"),
            Err(e) => match e {
                DecryptionError::GenericDecryptionError => assert!(false, "Should err InvalidUTF8DecryptionError"),
                DecryptionError::InvalidUTF8DecryptionError => assert!(true)
            }
        }
    }

    // #[test]
    // Not able to find any example that would make this err...
    // fn decrypt_err_when_decryption_error() {
    //     let key = Key::try_from("12345678901234567890123456789012").unwrap();
    //     let encrypted_value_and_iv = EncryptedValueAndIv {
    //         encrypted: encrypted,
    //         iv: iv
    //     }
    //     match decrypt(&key, encrypted_value_and_iv) {
    //         Ok(_) => assert!(false, "Should err GenericDecryptionError"),
    //         Err(e) => match e {
    //             DecryptionError::InvalidUTF8DecryptionError => assert!(false, GenericDecryptionError),
    //             DecryptionError::GenericDecryptionError => assert!(true)
    //         }
    //     }
    // }
}
