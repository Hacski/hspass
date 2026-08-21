use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use p256::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use sha1::Sha1;
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasskeyRecord {
    pub id: String,
    pub rp_id: String, // Relying Party ID e.g., "github.com"
    pub user_handle: Vec<u8>,
    pub username: String,
    pub private_key_pem: String,
    pub sign_count: u32,
    pub created_at: String,
}

/// FIDO2 / Passkey Emulator Engine
pub struct PasskeyEngine;

impl PasskeyEngine {
    /// Creates a new FIDO2 ECDSA (secp256r1 / P-256) keypair for a relying party domain
    pub fn create_passkey(rp_id: &str, username: &str, user_handle: &[u8]) -> Result<PasskeyRecord> {
        let signing_key = SigningKey::random(&mut OsRng);
        let pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| anyhow!("Failed to encode passkey private key: {}", e))?;

        let id = format!("{}:{}", rp_id, username);

        Ok(PasskeyRecord {
            id,
            rp_id: rp_id.to_string(),
            user_handle: user_handle.to_vec(),
            username: username.to_string(),
            private_key_pem: pem.to_string(),
            sign_count: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Sign WebAuthn / CTAP2 assertion challenge using stored passkey
    pub fn sign_assertion(record: &mut PasskeyRecord, challenge: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_pkcs8_pem(&record.private_key_pem)
            .map_err(|e| anyhow!("Failed to decode passkey key: {}", e))?;

        record.sign_count += 1;

        // Hash challenge with SHA256 before signing
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(&record.sign_count.to_be_bytes());
        let digest = hasher.finalize();

        let signature: Signature = signing_key.sign(&digest);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Virtual YubiKey & HMAC-SHA1 Challenge-Response Engine
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct YubiKeySlotSecret {
    pub secret: [u8; 20], // 160-bit HMAC-SHA1 key for YubiKey Slot 1 or 2
}

pub struct VirtualYubiKey {
    pub slot_secret: YubiKeySlotSecret,
}

impl VirtualYubiKey {
    pub fn new(secret_bytes: [u8; 20]) -> Self {
        Self {
            slot_secret: YubiKeySlotSecret { secret: secret_bytes },
        }
    }

    pub fn generate_random_slot() -> Self {
        let mut secret = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::new(secret)
    }

    /// Perform YubiKey HMAC-SHA1 Challenge-Response for 64-byte challenge
    pub fn challenge_response(&self, challenge: &[u8]) -> Result<[u8; 20]> {
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(&self.slot_secret.secret)
            .map_err(|e| anyhow!("HMAC initialization failed: {}", e))?;

        mac.update(challenge);
        let result = mac.finalize().into_bytes();

        let mut output = [0u8; 20];
        output.copy_from_slice(&result[..20]);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_creation_and_assertion() {
        let mut passkey = PasskeyEngine::create_passkey("github.com", "alice", b"user123").unwrap();
        let challenge = b"webauthn_random_server_challenge_nonce";
        let signature = PasskeyEngine::sign_assertion(&mut passkey, challenge).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(passkey.sign_count, 2);
    }

    #[test]
    fn test_yubikey_challenge_response() {
        let yubikey = VirtualYubiKey::generate_random_slot();
        let challenge = b"challenge_payload_from_host";
        let resp1 = yubikey.challenge_response(challenge).unwrap();
        let resp2 = yubikey.challenge_response(challenge).unwrap();
        assert_eq!(resp1, resp2);
    }
}
