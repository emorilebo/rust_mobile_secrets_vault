// Basic usage example for rust_mobile_secrets_vault

use rust_mobile_secrets_vault::{KeySource, SecretVault};
use std::path::Path;

fn main() -> rust_mobile_secrets_vault::Result<()> {
    // Generate a master key (in production, load from secure storage)
    use rand::{rngs::OsRng, RngCore};
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    // Create a vault
    let vault_path = Path::new("my_vault.yaml");
    let mut vault = SecretVault::new(
        KeySource::Bytes(key.to_vec()),
        vault_path,
        None, // No audit logging for this example
    )?;

    // Store a database password
    vault.set("database_password", b"super_secret_password")?;

    // Store an API key
    vault.set("api_key", b"sk_test_123456789")?;

    // Retrieve a secret
    if let Some(password) = vault.get("database_password")? {
        println!("Database password: {}", String::from_utf8_lossy(&password));
    }

    // Update a secret (creates a new version)
    vault.set("api_key", b"sk_live_987654321")?;

    // List all versions
    let versions = vault.list_versions("api_key")?;
    println!("API key versions: {:?}", versions);

    // Get a specific version
    if let Some(old_key) = vault.get_version("api_key", 1)? {
        println!("Old API key (v1): {}", String::from_utf8_lossy(&old_key));
    }

    // List all secret keys
    let keys = vault.list_keys();
    println!("All secrets: {:?}", keys);

    // Delete a secret
    vault.delete("database_password")?;

    // Clean up
    std::fs::remove_file(vault_path).ok();

    Ok(())
}
