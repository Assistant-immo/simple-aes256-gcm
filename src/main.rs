use ::simple_aes256_gcm::simple_aes256_gcm;


fn main() {
    let lorem_ipsum = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur sodales diam sagittis, dignissim est at, vehicula mi. Sed placerat sollicitudin sollicitudin. Donec et cursus sapien. Morbi bibendum, dui non fringilla mattis, nisi libero iaculis lectus, eget tincidunt est dui eu lorem. Praesent vitae enim nec sapien maximus porttitor non in risus. Maecenas nec accumsan sapien. Quisque placerat tempus mauris, nec vulputate mauris porttitor sed. Vivamus eu finibus elit. Suspendisse potenti. Quisque sagittis nibh non eros facilisis semper. Sed sit amet dictum orci. Vestibulum eget mi quis magna euismod dignissim. Aliquam erat volutpat. Quisque id magna non neque mattis mattis sit amet in arcu. Duis sagittis, tortor non imperdiet interdum, arcu tellus imperdiet elit, ac porttitor libero ipsum ac arcu. Sed convallis massa vel hendrerit vulputate.";
    let key = simple_aes256_gcm::Key::new("12345678901234567890123456789012").unwrap();

    let encrypted_value_and_iv = simple_aes256_gcm::encrypt(&key, lorem_ipsum).unwrap();

    println!("IV: {}", encrypted_value_and_iv.iv);
    println!("ENCRYPTED: {}", encrypted_value_and_iv.encrypted);
    let plaintext = simple_aes256_gcm::decrypt(&key, encrypted_value_and_iv).unwrap();
    println!("DECRYPTED: {}", plaintext);
}
