use argon2::{
    password_hash::rand_core::OsRng,
    Argon2, Params,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaChaNonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};

/// Key wrapper with automatic zeroization on drop to prevent RAM leaks
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub key: [u8; 32],
}

impl DerivedKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
pub enum EncryptionAlgorithm {
    #[default]
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Derives a 256-bit key from a master passphrase using Argon2id with memory-hard parameters
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    let mut derived = [0u8; 32];
    
    // Argon2id parameters: 64MB memory, 3 iterations, 4 parallelism lanes
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, salt, &mut derived)
        .map_err(|e| anyhow!("Argon2 derivation failure: {}", e))?;

    Ok(DerivedKey::new(derived))
}

/// Generates a cryptographically secure 16-byte salt for Argon2id
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a randomized 12-byte nonce for AEAD encryption
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext bytes using AES-256-GCM or ChaCha20Poly1305 with a randomized nonce
pub fn encrypt_bytes(
    algo: EncryptionAlgorithm,
    key: &DerivedKey,
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match algo {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow!("AES key init failed: {}", e))?;
            let gcm_nonce = Nonce::from_slice(nonce);
            let ciphertext = cipher
                .encrypt(gcm_nonce, plaintext)
                .map_err(|e| anyhow!("AES-GCM encryption error: {}", e))?;
            Ok(ciphertext)
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher_key = Key::from_slice(key.as_bytes());
            let cipher = ChaCha20Poly1305::new(cipher_key);
            let chacha_nonce = ChaChaNonce::from_slice(nonce);
            let ciphertext = cipher
                .encrypt(chacha_nonce, plaintext)
                .map_err(|e| anyhow!("ChaCha20Poly1305 encryption error: {}", e))?;
            Ok(ciphertext)
        }
    }
}

/// Decrypts ciphertext bytes using AES-256-GCM or ChaCha20Poly1305
pub fn decrypt_bytes(
    algo: EncryptionAlgorithm,
    key: &DerivedKey,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    match algo {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow!("AES key init failed: {}", e))?;
            let gcm_nonce = Nonce::from_slice(nonce);
            let plaintext = cipher
                .decrypt(gcm_nonce, ciphertext)
                .map_err(|e| anyhow!("Decryption failed - Invalid master passphrase or corrupt data (AES-GCM): {}", e))?;
            Ok(plaintext)
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher_key = Key::from_slice(key.as_bytes());
            let cipher = ChaCha20Poly1305::new(cipher_key);
            let chacha_nonce = ChaChaNonce::from_slice(nonce);
            let plaintext = cipher
                .decrypt(chacha_nonce, ciphertext)
                .map_err(|e| anyhow!("Decryption failed - Invalid master passphrase or corrupt data (ChaCha20): {}", e))?;
            Ok(plaintext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation_and_encryption() {
        let passphrase = b"super_secret_master_key_123!";
        let salt = generate_salt();
        let key = derive_key(passphrase, &salt).unwrap();
        let nonce = generate_nonce();
        let plaintext = b"Vault Secret Data Payload";

        let ciphertext = encrypt_bytes(EncryptionAlgorithm::Aes256Gcm, &key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_bytes(EncryptionAlgorithm::Aes256Gcm, &key, &nonce, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
