use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1};
use url::Url;

pub struct OtpEngine;

impl OtpEngine {
    /// Generate a 6-digit TOTP code given a raw secret bytes and timestamp
    pub fn generate_totp(secret: &[u8], seconds: u64) -> String {
        let step = 30;
        let digits = 6;
        let result = totp_custom::<Sha1>(step, digits, secret, seconds);
        format!("{:06}", result)
    }

    /// Helper to get current TOTP code and remaining seconds in 30-second window
    pub fn current_totp(secret: &[u8]) -> Result<(String, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();

        let remaining = 30 - (now % 30);
        let code = Self::generate_totp(secret, now);
        Ok((code, remaining))
    }

    /// Parse secret bytes from a base32 encoded string or otpauth:// URI
    pub fn parse_secret(secret_str: &str) -> Result<Vec<u8>> {
        let clean_secret = if secret_str.starts_with("otpauth://") {
            let url = Url::parse(secret_str)?;
            let pairs = url.query_pairs();
            let mut sec = None;
            for (k, v) in pairs {
                if k == "secret" {
                    sec = Some(v.to_string());
                    break;
                }
            }
            sec.ok_or_else(|| anyhow!("No secret parameter found in otpauth URI"))?
        } else {
            secret_str.to_string()
        };

        // Standardize Base32 decoding
        let secret_uppercase = clean_secret.to_uppercase().replace(' ', "");
        let bytes = base32_decode(&secret_uppercase)
            .ok_or_else(|| anyhow!("Invalid Base32 secret string"))?;
        Ok(bytes)
    }

    /// Format progress bar for terminal output [████████░░░░] 20s
    pub fn format_progress_bar(remaining_secs: u64) -> String {
        let total_blocks: usize = 15;
        let filled_blocks = ((remaining_secs as f64 / 30.0) * total_blocks as f64).round() as usize;
        let empty_blocks = total_blocks.saturating_sub(filled_blocks);

        let bar: String = "█".repeat(filled_blocks) + &"░".repeat(empty_blocks);
        format!("[{}] {:2}s", bar, remaining_secs)
    }
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }
        let val = alphabet.find(c)? as u64;
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            out.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation_and_uri_parsing() {
        let uri = "otpauth://totp/Google:alice@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google";
        let secret = OtpEngine::parse_secret(uri).unwrap();
        let (code, remaining) = OtpEngine::current_totp(&secret).unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);

        let bar = OtpEngine::format_progress_bar(15);
        assert!(bar.contains("█"));
        assert!(bar.contains("░"));
    }
}
