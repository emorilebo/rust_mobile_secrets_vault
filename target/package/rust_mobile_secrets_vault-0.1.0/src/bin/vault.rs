use anyhow::{Context, Result};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use rust_mobile_secrets_vault::cli::{Cli, Commands};
use rust_mobile_secrets_vault::{KeySource, SecretVault};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { key_out } => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let key_base64 = base64::encode(key);

            if let Some(path) = key_out {
                fs::write(&path, &key_base64).context("Failed to write master key file")?;
                println!("Master key written to {:?}", path);
            } else {
                println!("Master Key (SAVE THIS SECURELY): {}", key_base64);
            }

            // Initialize empty vault
            let key_source = KeySource::Bytes(key.to_vec());
            let vault = SecretVault::new(key_source, &cli.vault_path, cli.audit_path.as_deref())?;
            vault.save()?;
            println!("Initialized empty vault at {:?}", cli.vault_path);
        }
        _ => {
            // For other commands, we need to load the key
            let key_source = if let Some(path) = cli.key_path {
                KeySource::File(path)
            } else if let Some(env_var) = cli.key_env {
                KeySource::Env(env_var)
            } else {
                return Err(anyhow::anyhow!(
                    "Master key must be provided via --key-path or --key-env"
                ));
            };

            let mut vault = SecretVault::new(key_source, &cli.vault_path, cli.audit_path.as_deref())?;

            match cli.command {
                Commands::Set { key, value } => {
                    vault.set(&key, value.as_bytes())?;
                    println!("Secret '{}' set successfully.", key);
                }
                Commands::Get { key } => {
                    if let Some(value) = vault.get(&key)? {
                        println!("{}", String::from_utf8_lossy(&value));
                    } else {
                        println!("Secret '{}' not found.", key);
                    }
                }
                Commands::Delete { key } => {
                    vault.delete(&key)?;
                    println!("Secret '{}' deleted.", key);
                }
                Commands::Rotate {
                    new_key_path,
                    new_key_out,
                } => {
                    let mut new_key = [0u8; 32];
                    OsRng.fill_bytes(&mut new_key);
                    let new_key_base64 = base64::encode(new_key);

                    if let Some(path) = new_key_out {
                        fs::write(&path, &new_key_base64)
                            .context("Failed to write new master key file")?;
                        println!("New master key written to {:?}", path);
                    } else {
                        println!("New Master Key (SAVE THIS SECURELY): {}", new_key_base64);
                    }

                    let new_key_source = if let Some(path) = new_key_path {
                        KeySource::File(path)
                    } else {
                        KeySource::Bytes(new_key.to_vec())
                    };

                    vault.rotate(new_key_source)?;
                    println!("Vault rotated successfully.");
                }
                Commands::ListVersions { key } => {
                    let versions = vault.list_versions(&key)?;
                    println!("Versions for '{}': {:?}", key, versions);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
