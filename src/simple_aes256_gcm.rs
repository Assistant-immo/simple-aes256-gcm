pub mod simple_aes256_gcm {
    use aes_gcm::Aes256Gcm;
    use aead::{Aead, NewAead, generic_array::GenericArray};
    use std::fmt;
    use std::convert::TryInto;

    pub struct Key {
        pub u8_array: [u8; 32]
    }

    impl Key {
        pub fn new(key: &str) -> Result<Key, &'static str> {
            let u8_array: Result<[u8; 32], _> = key.as_bytes().try_into();
            match u8_array {
                Ok(value) => Ok(Key {
                    u8_array: value
                }),
                Err(_) => Err("Please provide a 32-bytes key")
            }
        }
    }

    pub struct Iv {
        pub u8_array: [u8; 12]
    }

    impl Iv {
        pub fn from_base64(base64_iv: &str) -> Result<Iv, &'static str> {
            let encrypted_value = match base64::decode(base64_iv) {
                Ok(data) => data,
                Err(_) => return Err("Invalid Base64 string")
            };

            let u8_array: Result<[u8; 12], _> = encrypted_value.as_slice().try_into();
            match u8_array {
                Ok(value) => Ok(Iv {
                    u8_array: value
                }),
                Err(_) => Err("Please provide a base64 encoeded 12-byte iv")
            }
        }

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

    impl Encrypted {

        pub fn from_base64(base64_encrypted: &str) -> Result<Encrypted, &'static str> {
            match base64::decode(base64_encrypted) {
                Ok(data) => Ok(
                    Encrypted {
                        u8_vec: data
                    }
                ),
                Err(_) => Err("Invalid Base64 string")
            }
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
}
