use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use rust_mobile_secrets_vault::cli::{Cli, Commands};
use rust_mobile_secrets_vault::{KeySource, Result, SecretVault};
use std::fs;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { key_out } => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let key_base64 = general_purpose::STANDARD.encode(key);

            if let Some(path) = key_out {
                fs::write(&path, &key_base64)
                    .map_err(|e| rust_mobile_secrets_vault::VaultError::Io(e))?;
                println!("✓ Master key written to {:?}", path);
            } else {
                println!("Master Key (SAVE THIS SECURELY!):");
                println!("{}", key_base64);
                println!("\nStore this key in a secure location.");
            }

            // Initialize empty vault
            let key_source = KeySource::Bytes(key.to_vec());
            let vault = SecretVault::new(key_source, &cli.vault_path, cli.audit_path.as_deref())?;
            vault.save()?;
            println!("✓ Initialized empty vault at {:?}", cli.vault_path);
        }
        _ => {
            // For other commands, we need to load the key
            let key_source = if let Some(path) = cli.key_path {
                KeySource::File(path)
            } else if let Some(env_var) = cli.key_env {
                KeySource::Env(env_var)
            } else {
                return Err(rust_mobile_secrets_vault::VaultError::KeyLoadError(
                    "Master key must be provided via --key-path or --key-env".to_string(),
                ));
            };

            let mut vault =
                SecretVault::new(key_source, &cli.vault_path, cli.audit_path.as_deref())?;

            match cli.command {
                Commands::Set { key, value } => {
                    vault.set(&key, value.as_bytes())?;
                    println!("✓ Secret '{}' set successfully", key);
                }
                Commands::Get { key } => {
                    if let Some(value) = vault.get(&key)? {
                        let value_str = String::from_utf8_lossy(&value);
                        println!("{}", value_str);
                    } else {
                        eprintln!("Secret '{}' not found", key);
                        std::process::exit(1);
                    }
                }
                Commands::Delete { key } => {
                    vault.delete(&key)?;
                    println!("✓ Secret '{}' deleted", key);
                }
                Commands::Rotate {
                    new_key_path,
                    new_key_out,
                } => {
                    let (new_key, new_key_source) = if let Some(path) = new_key_path {
                        let content = fs::read_to_string(&path)
                            .map_err(|e| rust_mobile_secrets_vault::VaultError::Io(e))?;
                        let decoded = general_purpose::STANDARD.decode(content.trim())?;
                        (None, KeySource::Bytes(decoded))
                    } else {
                        let mut key = [0u8; 32];
                        OsRng.fill_bytes(&mut key);
                        (Some(key), KeySource::Bytes(key.to_vec()))
                    };

                    vault.rotate(new_key_source)?;

                    if let Some(key_bytes) = new_key {
                        let new_key_base64 = general_purpose::STANDARD.encode(key_bytes);
                        if let Some(path) = new_key_out {
                            fs::write(&path, &new_key_base64)
                                .map_err(|e| rust_mobile_secrets_vault::VaultError::Io(e))?;
                            println!("✓ New master key written to {:?}", path);
                        } else {
                            println!("New Master Key (SAVE THIS SECURELY!):");
                            println!("{}", new_key_base64);
                        }
                    }

                    println!("✓ Vault rotated successfully");
                }
                Commands::ListVersions { key } => {
                    let versions = vault.list_versions(&key)?;
                    if versions.is_empty() {
                        println!("No versions found for '{}'", key);
                    } else {
                        println!("Versions for '{}': {:?}", key, versions);
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
