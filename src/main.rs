use hspass::crypto::{derive_key, generate_salt, EncryptionAlgorithm, encrypt_bytes, decrypt_bytes};

fn main() {
    println!("hspass v0.1.0 Core Cryptographic Engine");
    let salt = generate_salt();
    let key = derive_key(b"master_password", &salt).unwrap();
    let nonce = [0u8; 12];
    let encrypted = encrypt_bytes(EncryptionAlgorithm::Aes256Gcm, &key, &nonce, b"secret test").unwrap();
    let decrypted = decrypt_bytes(EncryptionAlgorithm::Aes256Gcm, &key, &nonce, &encrypted).unwrap();
    println!("Decrypted test payload: {}", String::from_utf8(decrypted).unwrap());
}
