# Simple AES256-GCM

## Description

`simple-aes256-gcm` is a crate built on top of `aes-gcm` exposing a easy-to-use aes256-gcm encryption API.

## Usage

```
use ::SimpleAES256Gcm::SimpleAES256Gcm;

let key =
SimpleAES256Gcm::Key::new("a_key_that_is_32_byte_long_exact").unwrap();

let lorem_ipsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur sodales diam sagittis, dignissim est at, vehicula mi. Sed placerat sollicitudin sollicitudin."

let encrypted_value_and_iv = SimpleAES256Gcm::encrypt(&key, lorem_ipsum);

println!("IV: {}", encrypted_value_and_iv.iv);
println!("ENCRYPTED: {}", encrypted_value_and_iv.encrypted);
let plaintext = SimpleAES256Gcm::decrypt(&key, encrypted_value_and_iv).unwrap();
println!("DECRYPTED: {}", plaintext);

```
