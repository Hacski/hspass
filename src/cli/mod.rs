use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "hspass")]
#[command(author = "Hacski")]
#[command(version = "0.1.0")]
#[command(about = "Zero-Knowledge CLI Password Manager, Passkey Emulator & Offline Blockchain Backup Engine", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new local vault directory (~/.hspass/vault.enc)
    Init {
        /// Algorithm to use: aes-gcm or chacha20
        #[arg(long, default_value = "aes-gcm")]
        algorithm: String,
    },

    /// Generate and securely store a new credential password
    Generate {
        /// Service/Domain name (e.g. github.com)
        service: String,
        /// Username or email address
        #[arg(short, long)]
        username: Option<String>,
        /// Password length
        #[arg(short, long, default_value_t = 24)]
        length: usize,
        /// Avoid ambiguous characters (0, O, I, l)
        #[arg(long)]
        no_ambiguous: bool,
    },

    /// Securely retrieve and view a stored credential
    Get {
        /// Service name
        service: String,
    },

    /// List all stored services in your vault
    List,

    /// Update an existing stored credential
    Update {
        /// Service name
        service: String,
        /// New username
        #[arg(short, long)]
        username: Option<String>,
        /// New password (if omitted, interactive prompt will ask)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Delete a credential from your vault
    Delete {
        /// Service name
        service: String,
    },

    /// Display live TOTP / HOTP single-use 6-digit codes with visual progress bar
    Otp {
        /// Service name or otpauth:// URI
        service: String,
        /// Add a new secret URI for this service
        #[arg(short, long)]
        add_secret: Option<String>,
    },

    /// FIDO2 / Passkey software emulator operations
    Passkey {
        #[command(subcommand)]
        action: PasskeyCommands,
    },

    /// Scan local vault for weak, duplicate, or short passwords
    Audit,

    /// Compile vault state into signed offline Merkle payload & display Air-Gapped QR code
    Blockchain {
        #[command(subcommand)]
        action: BlockchainCommands,
    },

    /// Launch full interactive Terminal UI mode (TUI)
    Tui,
}

#[derive(Subcommand, Debug)]
pub enum PasskeyCommands {
    /// Register a new FIDO2 passkey for a target domain/RP
    Register {
        /// Relying party domain (e.g. github.com)
        domain: String,
        /// User login name
        #[arg(short, long)]
        username: String,
    },
    /// Sign a WebAuthn assertion challenge locally
    Sign {
        /// Relying party domain
        domain: String,
        /// User login name
        #[arg(short, long)]
        username: String,
        /// Hex/Base64 server challenge string
        challenge: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BlockchainCommands {
    /// Export signed Merkle state & encrypted anchor transaction payload
    Export {
        /// Display payload as terminal ASCII QR Code
        #[arg(long)]
        qr: bool,
    },
    /// Verify an exported blockchain payload's Merkle root and signature
    Verify {
        /// Path to JSON payload file
        file: String,
    },
}
