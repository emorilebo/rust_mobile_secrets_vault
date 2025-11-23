# Rust Mobile Secrets Vault

A secure, encrypted secrets vault for mobile backends and embedded Rust services with versioning and key rotation support.

## Features

- **🔐 AES-256-GCM Encryption** - Industry-standard authenticated encryption
- **📝 Secret Versioning** - Keep history of all secret versions
- **🔄 Key Rotation** - Securely rotate encryption keys without data loss
- **📊 Audit Logging** - Track all vault operations
- **🛠️ CLI Tool** - Easy command-line management
- **📦 Builder Pattern** - Flexible vault configuration

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust_mobile_secrets_vault = "0.2.0"
```

## Quick Start

### Using the Library

```rust
use rust_mobile_secrets_vault::{KeySource, SecretVault};
use std::path::Path;

// Create a vault
let key = vec![42u8; 32]; // In production, generate securely
let mut vault = SecretVault::new(
    KeySource::Bytes(key),
    Path::new("vault.yaml"),
    None
)?;

// Store a secret
vault.set("api_key", b"my_secret_key")?;

// Retrieve it
if let Some(secret) = vault.get("api_key")? {
    println!("API Key: {}", String::from_utf8_lossy(&secret));
}
```

### Using the CLI

```bash
# Initialize a new vault
vault init --key-out master.key

# Store a secret
vault set database_password "supersecret" --key-path master.key

# Retrieve a secret
vault get database_password --key-path master.key

# Rotate the master key
vault rotate --key-path master.key --new-key-out new_master.key

# List versions
vault list-versions database_password --key-path new_master.key
```

## Advanced Usage

### Builder Pattern

```rust
let vault = SecretVault::builder()
    .master_key(KeySource::Env("VAULT_KEY".to_string()))
    .vault_path("secure_vault.yaml")
    .audit_path("audit.log")
    .build()?;
```

### Version Management

```rust
// Update a secret (creates new version)
vault.set("api_key", b"new_value")?;

// Get specific version
if let Some(old_value) = vault.get_version("api_key", 1)? {
    println!("Version 1: {}", String::from_utf8_lossy(&old_value));
}

// List all versions
let versions = vault.list_versions("api_key")?;
println!("Available versions: {:?}", versions);
```

### Key Rotation

```rust
// Generate new key
let new_key = vec![/* 32 secure random bytes */];

// Rotate (re-encrypts all secrets)
vault.rotate(KeySource::Bytes(new_key))?;
```

## Security Best Practices

### ⚠️  Master Key Protection
- **Never** commit master keys to version control
- Store in environment variables or secure key management systems
- Use different keys for development, staging, and production

### 🔒 Vault File Security
- Protect vault files with appropriate file system permissions
- Consider encrypting at rest in production environments
- Regular backups recommended

### 🔄 Regular Key Rotation
- Rotate master keys periodically (e.g., every 90 days)
- Rotate immediately if key compromise is suspected
- Test rotation in non-production environments first

### 📝 Audit Logging
- Enable audit logging in production
- Monitor logs for suspicious activity
- Store audit logs in a secure, append-only location

## CLI Reference

| Command | Description |
|---------|-------------|
| `init` | Initialize a new vault and generate master key |
| `set <key> <value>` | Store or update a secret |
| `get <key>` | Retrieve the latest version of a secret |
| `delete <key>` | Delete a secret and all its versions |
| `rotate` | Rotate the master encryption key |
| `list-versions <key>` | List all versions for a secret |

### CLI Options

- `--vault-path <PATH>` - Path to vault file (default: `vault.yaml`)
- `--key-path <PATH>` - Path to master key file
- `--key-env <VAR>` - Environment variable containing master key
- `--audit-path <PATH>` - Path to audit log file

## Examples

See the [`examples/`](examples/) directory for complete working examples:

- **basic_usage.rs** - Simple vault operations
- **key_rotation.rs** - Master key rotation demonstration
- **builder_pattern.rs** - Using the builder API

Run examples with:

```bash
cargo run --example basic_usage
cargo run --example key_rotation
cargo run --example builder_pattern
```

## Error Handling

The library uses a custom `VaultError` type for precise error handling:

```rust
match vault.get("missing_key") {
    Ok(Some(value)) => println!("Found: {:?}", value),
    Ok(None) => println!("Secret not found"),
    Err(VaultError::DecryptionFailed(msg)) => eprintln!("Decryption error: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Troubleshooting

### "Decryption failed" error
- Verify you're using the correct master key
- Check if the vault file is corrupted
- Ensure the key hasn't changed since encryption

### "Invalid key size" error
- Master key must be exactly 32 bytes
- If using base64, ensure proper encoding

### "Secret not found"
- Verify the secret key name (case-sensitive)
- Check if the secret was deleted

## Performance

- Encryption/decryption: ~1-5 µs per operation
- File I/O dominates performance for vault operations
- Consider batching operations when possible

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code is formatted (`cargo fmt`)
- No clippy warnings (`cargo clippy`)

## License

MIT OR Apache-2.0

## Changelog

### 0.2.0 (Latest)
- **New Features:**
  - Custom error types (`VaultError`) for better type safety
  - Builder pattern API for flexible vault configuration
  - `get_version()` method to retrieve specific secret versions
  - `list_keys()` method to list all secrets in vault
  - Input validation for secret keys
- **Improvements:**
  - Enhanced documentation with examples
  - Better error messages
  - Improved CLI output with visual feedback
  - Comprehensive examples in `examples/` directory
- **Documentation:**
  - Complete README rewrite with security best practices
  - Added troubleshooting guide
  - CLI reference table
  - Performance notes

### 0.1.0 (Initial Release)
- AES-256-GCM encryption
- Secret versioning
- Key rotation
- Audit logging
- CLI tool
