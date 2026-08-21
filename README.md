# hspass 🔒

> Zero-Knowledge CLI Password Manager, FIDO2/Passkey Emulator, TOTP/HOTP Authenticator & Offline Blockchain Backup Engine.

Built with **Rust**, featuring zero-server client-side cryptography (`Argon2id`, `AES-256-GCM`, `ChaCha20-Poly1305`), strict RAM zeroization (`zeroize`), software FIDO2 passkey emulation (`P-256 / secp256r1`), Virtual YubiKey HMAC-SHA1 challenge-response, TOTP/HOTP code generation, and offline SHA3-256 Merkle tree blockchain state anchoring with Air-Gapped QR export.

---

## 🚀 Features

- **Zero-Knowledge Vault Engine**: Key derivation via Argon2id (memory-hard 64MB) with AES-256-GCM or ChaCha20Poly1305 authenticated encryption stored at `~/.hspass/vault.enc`. Zero cloud dependencies or servers.
- **RAM Security**: Automatic zeroing out of sensitive variables in memory using Rust `zeroize`.
- **Advanced Password Generator**: Rules for length, custom character sets, and ambig-free characters.
- **Local Health Audit**: Offline scanner for weak, short, and duplicate reused passwords.
- **FIDO2 / Passkey Emulator**: Local CTAP2/WebAuthn ECDSA secp256r1 keypair generation and assertion signing.
- **Virtual YubiKey Engine**: HMAC-SHA1 challenge-response slot emulation.
- **TOTP / HOTP Authenticator**: `otpauth://` URI parsing and terminal progress bars for 30s TOTP windows.
- **Offline Blockchain Anchoring**: Merkle tree calculation (`SHA3-256`), local Secp256k1 signature payload generation, and Air-Gapped animated ASCII QR code exports.
- **Terminal UI Dashboard**: Built-in interactive TUI (`ratatui` + `crossterm`).

---

## 🛠️ Usage & Commands

```bash
# Initialize a new encrypted vault
hspass init --algorithm aes-gcm

# Generate a secure 24-character password and save to vault
hspass generate github.com --username alice --length 24

# List stored services in vault
hspass list

# Retrieve credential details
hspass get github.com

# Display live TOTP tokens with visual progress bar
hspass otp github.com --add-secret "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# FIDO2 Passkey Operations
hspass passkey register github.com --username alice
hspass passkey sign github.com --username alice <CHALLENGE_HEX>

# Security Audit Scan
hspass audit

# Export Signed Blockchain Anchor Payload & Air-Gapped QR Code
hspass blockchain export --qr

# Interactive Terminal UI
hspass tui
```

---

## 📦 Building from Source

```bash
git clone https://github.com/Hacski/hspass.git
cd hspass
cargo build --release
./target/release/hspass --help
```