# Rust Mobile Secrets Vault

A secure, encrypted secrets vault for mobile-backend or embedded Rust services.

## Features

- **AES-256-GCM Encryption**: Authenticated encryption for all secrets.
- **Versioning**: Keeps history of secret versions.
- **Key Rotation**: Securely rotate the master key without losing data.
- **Audit Logging**: Tracks all access and modifications.
- **CLI Tool**: Easy management of secrets.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust_mobile_secrets_vault = "0.1.0"
```

To install the CLI:

```bash
cargo install --path .
```

## Usage

### CLI

1.  **Initialize the vault:**
    ```bash
    vault init --key-out master.key
    ```

2.  **Set a secret:**
    ```bash
    vault set db_password "supersecret" --key-path master.key
    ```

3.  **Get a secret:**
    ```bash
    vault get db_password --key-path master.key
    ```

4.  **Rotate master key:**
    ```bash
    vault rotate --key-path master.key --new-key-out new_master.key
    ```

### Rust API

```rust
use rust_mobile_secrets_vault::{SecretVault, KeySource};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let key_source = KeySource::Env("MASTER_KEY".to_string());
    let vault_path = Path::new("vault.yaml");
    
    let mut vault = SecretVault::new(key_source, vault_path, None)?;
    
    vault.set("api_key", b"123456")?;
    
    if let Some(secret) = vault.get("api_key")? {
        println!("Secret: {:?}", String::from_utf8_lossy(&secret));
    }
    
    Ok(())
}
```

## Security Best Practices

- **Master Key Protection**: Never commit your master key to version control. Inject it via environment variables or a secure file in production.
- **Vault File**: The `vault.yaml` file contains encrypted data, but should still be protected with file system permissions.
- **Rotation**: Rotate your master key regularly.

## License

MIT OR Apache-2.0
