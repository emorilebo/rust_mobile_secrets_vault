// Example using the builder pattern

use rand::{rngs::OsRng, RngCore};
use rust_mobile_secrets_vault::{KeySource, SecretVault};
use std::path::Path;

fn main() -> rust_mobile_secrets_vault::Result<()> {
    // Generate a master key
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    // Build vault with custom configuration
    let vault_path = Path::new("builder_vault.yaml");
    let audit_path = Path::new("audit.log");

    let mut vault = SecretVault::builder()
        .master_key(KeySource::Bytes(key.to_vec()))
        .vault_path(vault_path)
        .audit_path(audit_path)
        .build()?;

    println!("✓ Built vault with audit logging enabled");

    // Store secrets
    vault.set("config_key", b"configuration_value")?;
    vault.set("token", b"auth_token_12345")?;

    // Retrieve secret
    if let Some(config) = vault.get("config_key")? {
        println!("Config: {}", String::from_utf8_lossy(&config));
    }

    // Check audit log
    if audit_path.exists() {
        let audit_content = std::fs::read_to_string(audit_path)?;
        println!("\nAudit log entries:");
        for line in audit_content.lines().take(5) {
            println!("  {}", line);
        }
    }

    // Clean up
    std::fs::remove_file(vault_path).ok();
    std::fs::remove_file(audit_path).ok();

    Ok(())
}
