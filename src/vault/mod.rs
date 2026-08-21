use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};

use crate::crypto::{
    decrypt_bytes, derive_key, encrypt_bytes, generate_nonce, generate_salt,
    EncryptionAlgorithm,
};

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub id: String,
    pub service: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EncryptedVaultContainer {
    pub version: u32,
    pub salt: [u8; 16],
    pub algorithm: EncryptionAlgorithm,
    pub nonce: [u8; 12],
    pub encrypted_payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultData {
    pub credentials: HashMap<String, Credential>,
    pub passkeys: HashMap<String, Vec<u8>>, // Serialized passkey keypairs/metadata
    pub totp_entries: HashMap<String, String>, // service -> otpauth URI
}

pub struct VaultManager {
    pub vault_path: PathBuf,
}

impl VaultManager {
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        let dir = home.join(".hspass");
        fs::create_dir_all(&dir)?;
        Ok(dir.join("vault.enc"))
    }

    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let vault_path = match path {
            Some(p) => p,
            None => Self::default_path()?,
        };
        Ok(Self { vault_path })
    }

    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    pub fn initialize(&self, passphrase: &[u8], algo: EncryptionAlgorithm) -> Result<()> {
        if self.exists() {
            return Err(anyhow!("Vault already exists at {:?}", self.vault_path));
        }

        let salt = generate_salt();
        let key = derive_key(passphrase, &salt)?;
        let nonce = generate_nonce();

        let initial_data = VaultData::default();
        let serialized = serde_json::to_vec(&initial_data)?;

        let ciphertext = encrypt_bytes(algo, &key, &nonce, &serialized)?;

        let container = EncryptedVaultContainer {
            version: 1,
            salt,
            algorithm: algo,
            nonce,
            encrypted_payload: ciphertext,
        };

        let file_bytes = bincode::serialize(&container)?;
        if let Some(parent) = self.vault_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.vault_path, file_bytes)?;

        Ok(())
    }

    pub fn read_vault(&self, passphrase: &[u8]) -> Result<VaultData> {
        if !self.exists() {
            return Err(anyhow!("Vault file not found at {:?}", self.vault_path));
        }

        let file_bytes = fs::read(&self.vault_path)
            .with_context(|| format!("Failed to read vault file at {:?}", self.vault_path))?;
        let container: EncryptedVaultContainer = bincode::deserialize(&file_bytes)
            .with_context(|| "Failed to parse vault format. Vault may be corrupted.")?;

        let key = derive_key(passphrase, &container.salt)?;
        let decrypted_bytes = decrypt_bytes(
            container.algorithm,
            &key,
            &container.nonce,
            &container.encrypted_payload,
        )?;

        let vault_data: VaultData = serde_json::from_slice(&decrypted_bytes)
            .with_context(|| "Failed to parse decrypted vault data JSON")?;

        Ok(vault_data)
    }

    pub fn save_vault(&self, passphrase: &[u8], data: &VaultData) -> Result<()> {
        let container: EncryptedVaultContainer = if self.exists() {
            let file_bytes = fs::read(&self.vault_path)?;
            bincode::deserialize(&file_bytes).unwrap_or_default()
        } else {
            EncryptedVaultContainer {
                version: 1,
                salt: generate_salt(),
                algorithm: EncryptionAlgorithm::Aes256Gcm,
                nonce: generate_nonce(),
                encrypted_payload: vec![],
            }
        };

        let key = derive_key(passphrase, &container.salt)?;
        let new_nonce = generate_nonce();
        let serialized = serde_json::to_vec(data)?;

        let ciphertext = encrypt_bytes(container.algorithm, &key, &new_nonce, &serialized)?;

        let updated_container = EncryptedVaultContainer {
            version: container.version,
            salt: container.salt,
            algorithm: container.algorithm,
            nonce: new_nonce,
            encrypted_payload: ciphertext,
        };

        let file_bytes = bincode::serialize(&updated_container)?;
        fs::write(&self.vault_path, file_bytes)?;

        Ok(())
    }
}
