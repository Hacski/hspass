use anyhow::{anyhow, Result};
use clap::Parser;
use inquire::Password;

use hspass::audit::run_vault_audit;
use hspass::blockchain::BlockchainBackupEngine;
use hspass::cli::{BlockchainCommands, Cli, Commands, PasskeyCommands};
use hspass::crypto::EncryptionAlgorithm;
use hspass::generator::{generate_password, PasswordGeneratorOptions};
use hspass::otp::OtpEngine;
use hspass::passkey::PasskeyEngine;
use hspass::tui::run_tui;
use hspass::vault::{Credential, VaultManager};

fn prompt_passphrase(prompt: &str) -> Result<String> {
    Password::new(prompt)
        .without_confirmation()
        .prompt()
        .map_err(|e| anyhow!("Failed to prompt for passphrase: {}", e))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = VaultManager::new(None)?;

    match cli.command {
        Commands::Init { algorithm } => {
            if manager.exists() {
                println!("Vault already exists at {:?}", manager.vault_path);
                return Ok(());
            }

            let algo = match algorithm.to_lowercase().as_str() {
                "chacha20" | "chacha20poly1305" => EncryptionAlgorithm::ChaCha20Poly1305,
                _ => EncryptionAlgorithm::Aes256Gcm,
            };

            let pass = Password::new("Create Master Passphrase: ")
                .with_custom_confirmation_message("Confirm Master Passphrase: ")
                .with_custom_confirmation_error_message("Passphrases do not match!")
                .prompt()
                .map_err(|e| anyhow!("Passphrase creation failed: {}", e))?;

            manager.initialize(pass.as_bytes(), algo)?;
            println!("🔒 Successfully initialized zero-knowledge vault at {:?}", manager.vault_path);
        }

        Commands::Generate {
            service,
            username,
            length,
            no_ambiguous,
        } => {
            let opts = PasswordGeneratorOptions {
                length,
                avoid_ambiguous: no_ambiguous,
                ..Default::default()
            };
            let password = generate_password(&opts);
            let user = username.unwrap_or_else(|| "default".to_string());

            println!("🔑 Generated Password for {}:", service);
            println!("   {}", password);

            if manager.exists() {
                if let Ok(pass) = prompt_passphrase("Enter Master Passphrase to save: ") {
                    if let Ok(mut vault) = manager.read_vault(pass.as_bytes()) {
                        let cred = Credential {
                            id: service.clone(),
                            service: service.clone(),
                            username: user,
                            password,
                            url: None,
                            notes: None,
                            tags: vec![],
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                        };
                        vault.credentials.insert(service.clone(), cred);
                        manager.save_vault(pass.as_bytes(), &vault)?;
                        println!("✔ Saved credential to encrypted vault.");
                    }
                }
            }
        }

        Commands::Get { service } => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let vault = manager.read_vault(pass.as_bytes())?;

            if let Some(cred) = vault.credentials.get(&service) {
                println!("\n🔑 Credential Details for [{}]:", service);
                println!("   Username: {}", cred.username);
                println!("   Password: {}", cred.password);
                if let Some(url) = &cred.url {
                    println!("   URL:      {}", url);
                }
            } else {
                println!("❌ Service '{}' not found in vault.", service);
            }
        }

        Commands::List => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let vault = manager.read_vault(pass.as_bytes())?;

            println!("\n📋 Vault Credentials ({} entries):", vault.credentials.len());
            for (service, cred) in &vault.credentials {
                println!("   • {} ({})", service, cred.username);
            }
        }

        Commands::Update {
            service,
            username,
            password,
        } => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let mut vault = manager.read_vault(pass.as_bytes())?;

            if let Some(cred) = vault.credentials.get_mut(&service) {
                if let Some(u) = username {
                    cred.username = u;
                }
                if let Some(p) = password {
                    cred.password = p;
                }
                cred.updated_at = chrono::Utc::now();
                manager.save_vault(pass.as_bytes(), &vault)?;
                println!("✔ Updated credential for '{}'.", service);
            } else {
                println!("❌ Service '{}' not found in vault.", service);
            }
        }

        Commands::Delete { service } => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let mut vault = manager.read_vault(pass.as_bytes())?;

            if vault.credentials.remove(&service).is_some() {
                manager.save_vault(pass.as_bytes(), &vault)?;
                println!("✔ Removed credential for '{}'.", service);
            } else {
                println!("❌ Service '{}' not found in vault.", service);
            }
        }

        Commands::Otp { service, add_secret } => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let mut vault = manager.read_vault(pass.as_bytes())?;

            if let Some(sec_str) = add_secret {
                vault.totp_entries.insert(service.clone(), sec_str.clone());
                manager.save_vault(pass.as_bytes(), &vault)?;
                println!("✔ Saved TOTP secret for '{}'.", service);
            }

            if let Some(secret_str) = vault.totp_entries.get(&service) {
                let secret_bytes = OtpEngine::parse_secret(secret_str)?;
                let (code, remaining) = OtpEngine::current_totp(&secret_bytes)?;
                let progress = OtpEngine::format_progress_bar(remaining);

                println!("\n⏰ Live TOTP for [{}]:", service);
                println!("   Code:     {}", code);
                println!("   Time:     {}", progress);
            } else {
                println!("❌ No TOTP secret registered for '{}'. Use --add-secret to add one.", service);
            }
        }

        Commands::Passkey { action } => match action {
            PasskeyCommands::Register { domain, username } => {
                let pass = prompt_passphrase("Enter Master Passphrase: ")?;
                let mut vault = manager.read_vault(pass.as_bytes())?;

                let record = PasskeyEngine::create_passkey(&domain, &username, username.as_bytes())?;
                let serialized = serde_json::to_vec(&record)?;
                vault.passkeys.insert(record.id.clone(), serialized);

                manager.save_vault(pass.as_bytes(), &vault)?;
                println!("🔑 Successfully registered FIDO2 Passkey for domain: {}", domain);
                println!("   Key ID: {}", record.id);
            }
            PasskeyCommands::Sign { domain, username, challenge } => {
                let pass = prompt_passphrase("Enter Master Passphrase: ")?;
                let mut vault = manager.read_vault(pass.as_bytes())?;
                let key_id = format!("{}:{}", domain, username);

                if let Some(bytes) = vault.passkeys.get(&key_id) {
                    let mut record: hspass::passkey::PasskeyRecord = serde_json::from_slice(bytes)?;
                    let sig = PasskeyEngine::sign_assertion(&mut record, challenge.as_bytes())?;

                    let updated_bytes = serde_json::to_vec(&record)?;
                    vault.passkeys.insert(key_id, updated_bytes);
                    manager.save_vault(pass.as_bytes(), &vault)?;

                    println!("✔ Signed assertion challenge for {}:", domain);
                    println!("   Signature: {}", hex::encode(sig));
                } else {
                    println!("❌ Passkey for '{}:{}' not found.", domain, username);
                }
            }
        },

        Commands::Audit => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let vault = manager.read_vault(pass.as_bytes())?;
            let report = run_vault_audit(&vault);

            println!("\n🔍 Vault Security Health Scan:");
            println!("   Total Credentials:   {}", report.total_credentials);
            println!("   Weak Passwords:      {}", report.weak_passwords);
            println!("   Short Passwords:     {}", report.short_passwords);
            println!("   Reused Passwords:    {}", report.duplicate_passwords);

            if !report.issues.is_empty() {
                println!("\n⚠️ Security Issues Detected:");
                for issue in report.issues {
                    println!("   • [{:?}] {} ({}): {}", issue.severity, issue.service, issue.issue_type, issue.description);
                }
            } else {
                println!("\n✅ Excellent! No security risks found in vault.");
            }
        }

        Commands::Blockchain { action } => match action {
            BlockchainCommands::Export { qr } => {
                let pass = prompt_passphrase("Enter Master Passphrase: ")?;
                let vault = manager.read_vault(pass.as_bytes())?;
                let payload = BlockchainBackupEngine::generate_signed_blockchain_payload(&manager.vault_path, &vault)?;
                let json = serde_json::to_string_pretty(&payload)?;

                println!("\n⛓️ Signed Blockchain Anchor Payload:");
                println!("{}", json);

                if qr {
                    println!("\n📱 Air-Gapped QR Export Code:");
                    let qr_art = BlockchainBackupEngine::generate_qr_code(&json)?;
                    println!("{}", qr_art);
                }
            }
            BlockchainCommands::Verify { file } => {
                let content = std::fs::read_to_string(file)?;
                let payload: hspass::blockchain::BlockchainBackupPayload = serde_json::from_str(&content)?;
                println!("✔ Validated Blockchain Backup Payload Structure:");
                println!("   Merkle Root: {}", payload.vault_merkle_root);
                println!("   Signer:      {}", payload.signer_address);
                println!("   Entries:     {}", payload.entry_count);
            }
        },

        Commands::Tui => {
            let pass = prompt_passphrase("Enter Master Passphrase: ")?;
            let vault = manager.read_vault(pass.as_bytes())?;
            run_tui(&vault)?;
        }
    }

    Ok(())
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
