use sha3::{Sha3_256, Digest};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};
use k256::ecdsa::{SigningKey, signature::Signer, Signature};
use qrcode::QrCode;
use crate::vault::VaultData;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleNode {
    pub hash: String,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockchainBackupPayload {
    pub vault_merkle_root: String,
    pub timestamp: i64,
    pub entry_count: usize,
    pub signer_address: String,
    pub signature_hex: String,
    pub encrypted_vault_hash: String,
}

pub struct BlockchainBackupEngine;

impl BlockchainBackupEngine {
    /// Computes Merkle Tree root hash (SHA3-256) of vault entries
    pub fn compute_merkle_root(vault: &VaultData) -> String {
        let mut hashes: Vec<Vec<u8>> = vault
            .credentials
            .iter()
            .map(|(k, v)| {
                let mut hasher = Sha3_256::new();
                hasher.update(k.as_bytes());
                hasher.update(v.password.as_bytes());
                hasher.finalize().to_vec()
            })
            .collect();

        if hashes.is_empty() {
            let mut hasher = Sha3_256::new();
            hasher.update(b"empty_vault");
            return hex::encode(hasher.finalize());
        }

        hashes.sort();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                next_level.push(hasher.finalize().to_vec());
            }
            hashes = next_level;
        }

        hex::encode(&hashes[0])
    }

    /// Generates offline Ethereum/Solana-compatible ECDSA signature for vault state hash
    pub fn generate_signed_blockchain_payload(
        vault_path: &Path,
        vault: &VaultData,
    ) -> Result<BlockchainBackupPayload> {
        let file_bytes = fs::read(vault_path)?;
        let mut file_hasher = Sha3_256::new();
        file_hasher.update(&file_bytes);
        let encrypted_vault_hash = hex::encode(file_hasher.finalize());

        let merkle_root = Self::compute_merkle_root(vault);
        let timestamp = chrono::Utc::now().timestamp();

        // Generate local Secp256k1 keypair for signing anchor payload
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let signer_address = hex::encode(verifying_key.to_encoded_point(false).as_bytes());

        let mut msg_hasher = Sha3_256::new();
        msg_hasher.update(merkle_root.as_bytes());
        msg_hasher.update(timestamp.to_be_bytes());
        msg_hasher.update(encrypted_vault_hash.as_bytes());
        let message_hash = msg_hasher.finalize();

        let signature: Signature = signing_key.sign(&message_hash);
        let signature_hex = hex::encode(signature.to_bytes());

        Ok(BlockchainBackupPayload {
            vault_merkle_root: merkle_root,
            timestamp,
            entry_count: vault.credentials.len(),
            signer_address,
            signature_hex,
            encrypted_vault_hash,
        })
    }

    /// Generate terminal ASCII QR Code or chunked animated payload for Air-Gapped Sync
    pub fn generate_qr_code(data: &str) -> Result<String> {
        let code = QrCode::new(data.as_bytes())
            .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
        let string = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        Ok(string)
    }
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_and_qr_generation() {
        let vault = VaultData::default();
        let root = BlockchainBackupEngine::compute_merkle_root(&vault);
        assert!(!root.is_empty());

        let qr = BlockchainBackupEngine::generate_qr_code("hspass:test:backup").unwrap();
        assert!(qr.contains('\n'));
    }
}
