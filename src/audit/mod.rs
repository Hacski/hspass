use crate::vault::VaultData;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuditSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditIssue {
    pub service: String,
    pub username: String,
    pub severity: AuditSeverity,
    pub issue_type: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuditReport {
    pub total_credentials: usize,
    pub weak_passwords: usize,
    pub duplicate_passwords: usize,
    pub short_passwords: usize,
    pub issues: Vec<AuditIssue>,
}

pub fn run_vault_audit(vault: &VaultData) -> AuditReport {
    let mut report = AuditReport {
        total_credentials: vault.credentials.len(),
        ..Default::default()
    };

    let mut password_map: HashMap<&str, Vec<&str>> = HashMap::new();

    for (service, cred) in &vault.credentials {
        let pass = cred.password.as_str();

        // 1. Weak length check (< 12 chars)
        if pass.len() < 12 {
            report.short_passwords += 1;
            report.issues.push(AuditIssue {
                service: service.clone(),
                username: cred.username.clone(),
                severity: AuditSeverity::Critical,
                issue_type: "Short Password".to_string(),
                description: format!("Password is only {} characters long (minimum recommended is 12).", pass.len()),
            });
        }

        // 2. Simple patterns & dictionary checks
        let lower = pass.to_lowercase();
        if lower.contains("123456") || lower.contains("password") || lower.contains("qwerty") || lower.contains("admin") {
            report.weak_passwords += 1;
            report.issues.push(AuditIssue {
                service: service.clone(),
                username: cred.username.clone(),
                severity: AuditSeverity::Critical,
                issue_type: "Common Weak Pattern".to_string(),
                description: "Password contains extremely predictable sequence (e.g. '123456', 'password', 'qwerty').".to_string(),
            });
        }

        // Track duplicates
        password_map.entry(pass).or_default().push(service.as_str());
    }

    // 3. Duplicate password detection across accounts
    for (_pass, services) in password_map {
        if services.len() > 1 {
            report.duplicate_passwords += services.len();
            for service in services {
                if let Some(cred) = vault.credentials.get(service) {
                    report.issues.push(AuditIssue {
                        service: service.to_string(),
                        username: cred.username.clone(),
                        severity: AuditSeverity::Warning,
                        issue_type: "Reused Password".to_string(),
                        description: "Password is reused across multiple credentials in your vault.".to_string(),
                    });
                }
            }
        }
    }

    report
}
