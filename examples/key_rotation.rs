// Example demonstrating key rotation

use rand::{rngs::OsRng, RngCore};
use rust_mobile_secrets_vault::{KeySource, SecretVault};
use std::path::Path;

fn main() -> rust_mobile_secrets_vault::Result<()> {
    // Create initial master key
    let mut old_key = [0u8; 32];
    OsRng.fill_bytes(&mut old_key);

    // Create vault with secrets
    let vault_path = Path::new("rotation_vault.yaml");
    let mut vault = SecretVault::new(KeySource::Bytes(old_key.to_vec()), vault_path, None)?;

    // Add some secrets
    vault.set("secret1", b"value1")?;
    vault.set("secret2", b"value2")?;
    vault.set("secret3", b"value3")?;

    println!("✓ Created vault with 3 secrets");

    // Verify secrets can be read
    let value = vault.get("secret1")?.unwrap();
    println!(
        "✓ Secret1 (before rotation): {}",
        String::from_utf8_lossy(&value)
    );

    // Generate new master key
    let mut new_key = [0u8; 32];
    OsRng.fill_bytes(&mut new_key);

    // Rotate to new key
    println!("⟳ Rotating master key...");
    vault.rotate(KeySource::Bytes(new_key.to_vec()))?;
    println!("✓ Key rotation complete");

    // Verify secrets can still be read with new key
    let value = vault.get("secret1")?.unwrap();
    println!(
        "✓ Secret1 (after rotation): {}",
        String::from_utf8_lossy(&value)
    );

    let value2 = vault.get("secret2")?.unwrap();
    println!("  Secret2: {}", String::from_utf8_lossy(&value2));

    let value3 = vault.get("secret3")?.unwrap();
    println!("  Secret3: {}", String::from_utf8_lossy(&value3));

    println!("\n✓ All secrets successfully decrypted after rotation");

    // Clean up
    std::fs::remove_file(vault_path).ok();

    Ok(())
}
