use crate::audit::{AuditLogger, Operation};
use crate::encryption::{decrypt, encrypt, KEY_SIZE};
use crate::error::{Result, VaultError};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    pub fn new(key: Vec<u8>) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(VaultError::InvalidKeySize {
                expected: KEY_SIZE,
                found: key.len(),
            });
        }
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretEntry {
    pub encrypted_value: Vec<u8>,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub secrets: HashMap<String, Vec<SecretEntry>>,
}

/// A secure vault for storing encrypted secrets with versioning support.
pub struct SecretVault {
    master_key: MasterKey,
    path: PathBuf,
    data: VaultData,
    audit_logger: AuditLogger,
}

/// Source for loading the master encryption key.
pub enum KeySource {
    /// Load key from environment variable (base64 encoded)
    Env(String),
    /// Load key from file (base64 encoded)
    File(PathBuf),
    /// Use raw key bytes directly
    Bytes(Vec<u8>),
}

impl KeySource {
    pub fn load(self) -> Result<MasterKey> {
        let key_bytes = match self {
            KeySource::Env(var_name) => {
                let val = std::env::var(&var_name).map_err(|_| {
                    VaultError::KeyLoadError(format!("Environment variable {} not found", var_name))
                })?;
                general_purpose::STANDARD.decode(val)?
            }
            KeySource::File(path) => {
                let content = fs::read_to_string(&path).map_err(|e| {
                    VaultError::KeyLoadError(format!("Failed to read key file {:?}: {}", path, e))
                })?;
                general_purpose::STANDARD.decode(content.trim())?
            }
            KeySource::Bytes(bytes) => bytes,
        };
        MasterKey::new(key_bytes)
    }
}

/// Builder for creating a `SecretVault`.
pub struct VaultBuilder {
    master_key: Option<KeySource>,
    vault_path: Option<PathBuf>,
    audit_path: Option<PathBuf>,
}

impl VaultBuilder {
    /// Creates a new vault builder.
    pub fn new() -> Self {
        Self {
            master_key: None,
            vault_path: None,
            audit_path: None,
        }
    }

    /// Sets the master key source.
    pub fn master_key(mut self, key_source: KeySource) -> Self {
        self.master_key = Some(key_source);
        self
    }

    /// Sets the vault file path.
    pub fn vault_path(mut self, path: impl AsRef<Path>) -> Self {
        self.vault_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets the audit log file path.
    pub fn audit_path(mut self, path: impl AsRef<Path>) -> Self {
        self.audit_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Builds the vault.
    pub fn build(self) -> Result<SecretVault> {
        let master_key = self
            .master_key
            .ok_or_else(|| VaultError::KeyLoadError("Master key not provided".to_string()))?
            .load()?;

        let vault_path = self
            .vault_path
            .ok_or_else(|| VaultError::InvalidDataFormat("Vault path not provided".to_string()))?;

        let data = if vault_path.exists() {
            let file = File::open(&vault_path)?;
            let reader = BufReader::new(file);
            serde_yaml::from_reader(reader)?
        } else {
            VaultData::default()
        };

        Ok(SecretVault {
            master_key,
            path: vault_path,
            data,
            audit_logger: AuditLogger::new(self.audit_path.as_deref()),
        })
    }
}

impl Default for VaultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretVault {
    /// Creates a new vault builder.
    pub fn builder() -> VaultBuilder {
        VaultBuilder::new()
    }

    /// Creates a new secret vault.
    ///
    /// # Arguments
    /// * `master_key` - Source for the master encryption key
    /// * `path` - Path to the vault file
    /// * `audit_path` - Optional path to the audit log file
    pub fn new(master_key: KeySource, path: &Path, audit_path: Option<&Path>) -> Result<Self> {
        let mut builder = VaultBuilder::new().master_key(master_key).vault_path(path);

        if let Some(audit) = audit_path {
            builder = builder.audit_path(audit);
        }

        builder.build()
    }

    /// Saves the vault to disk.
    pub fn save(&self) -> Result<()> {
        let file = File::create(&self.path)?;
        serde_yaml::to_writer(file, &self.data)?;
        Ok(())
    }

    /// Sets or updates a secret.
    ///
    /// # Arguments
    /// * `key` - The secret identifier
    /// * `value` - The secret value to encrypt and store
    pub fn set(&mut self, key: &str, value: &[u8]) -> Result<()> {
        validate_secret_key(key)?;

        let encrypted_value = encrypt(self.master_key.as_bytes(), value)?;

        let entries = self.data.secrets.entry(key.to_string()).or_default();
        let version = entries.last().map(|e| e.version + 1).unwrap_or(1);

        entries.push(SecretEntry {
            encrypted_value,
            version,
            created_at: chrono::Utc::now(),
        });

        self.save()?;
        self.audit_logger.log(Operation::Set, key)?;
        Ok(())
    }

    /// Gets the latest version of a secret.
    ///
    /// # Arguments
    /// * `key` - The secret identifier
    ///
    /// # Returns
    /// The decrypted secret value, or None if the secret doesn't exist.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.audit_logger.log(Operation::Get, key)?;
        if let Some(entries) = self.data.secrets.get(key) {
            if let Some(latest) = entries.last() {
                let decrypted = decrypt(self.master_key.as_bytes(), &latest.encrypted_value)?;
                return Ok(Some(decrypted));
            }
        }
        Ok(None)
    }

    /// Gets a specific version of a secret.
    ///
    /// # Arguments
    /// * `key` - The secret identifier
    /// * `version` - The version number to retrieve
    ///
    /// # Returns
    /// The decrypted secret value for the specified version.
    pub fn get_version(&self, key: &str, version: u32) -> Result<Option<Vec<u8>>> {
        self.audit_logger.log(Operation::Get, key)?;

        if let Some(entries) = self.data.secrets.get(key) {
            if let Some(entry) = entries.iter().find(|e| e.version == version) {
                let decrypted = decrypt(self.master_key.as_bytes(), &entry.encrypted_value)?;
                return Ok(Some(decrypted));
            }
        }
        Ok(None)
    }

    /// Deletes a secret and all its versions.
    ///
    /// # Arguments
    /// * `key` - The secret identifier
    pub fn delete(&mut self, key: &str) -> Result<()> {
        if self.data.secrets.remove(key).is_some() {
            self.save()?;
            self.audit_logger.log(Operation::Delete, key)?;
        }
        Ok(())
    }

    /// Lists all available versions for a secret.
    ///
    /// # Arguments
    /// * `key` - The secret identifier
    ///
    /// # Returns
    /// A vector of version numbers, or an empty vector if the secret doesn't exist.
    pub fn list_versions(&self, key: &str) -> Result<Vec<u32>> {
        if let Some(entries) = self.data.secrets.get(key) {
            Ok(entries.iter().map(|e| e.version).collect())
        } else {
            Ok(vec![])
        }
    }

    /// Lists all secret keys in the vault.
    pub fn list_keys(&self) -> Vec<String> {
        self.data.secrets.keys().cloned().collect()
    }

    /// Rotates the master encryption key, re-encrypting all secrets.
    ///
    /// # Arguments
    /// * `new_master_source` - Source for the new master key
    pub fn rotate(&mut self, new_master_source: KeySource) -> Result<()> {
        let new_master_key = new_master_source.load()?;

        // Re-encrypt all secrets
        for (key, entries) in self.data.secrets.iter_mut() {
            for entry in entries.iter_mut() {
                let decrypted = decrypt(self.master_key.as_bytes(), &entry.encrypted_value)
                    .map_err(|e| match e {
                        VaultError::DecryptionFailed(msg) => VaultError::DecryptionFailed(format!(
                            "Failed to decrypt secret '{}' during rotation: {}",
                            key, msg
                        )),
                        other => other,
                    })?;
                let re_encrypted = encrypt(new_master_key.as_bytes(), &decrypted)?;
                entry.encrypted_value = re_encrypted;
            }
        }

        self.master_key = new_master_key;
        self.save()?;
        self.audit_logger.log(Operation::Rotate, "ALL")?;
        Ok(())
    }
}

/// Validates a secret key name.
fn validate_secret_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(VaultError::InvalidSecretKey(
            "Secret key cannot be empty".to_string(),
        ));
    }

    if key.contains('\0') {
        return Err(VaultError::InvalidSecretKey(
            "Secret key cannot contain null bytes".to_string(),
        ));
    }

    if key.len() > 256 {
        return Err(VaultError::InvalidSecretKey(
            "Secret key too long (max 256 characters)".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_vault_builder() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let key = vec![42u8; 32];

        let vault = SecretVault::builder()
            .master_key(KeySource::Bytes(key))
            .vault_path(&vault_path)
            .build();

        assert!(vault.is_ok());
    }

    #[test]
    fn test_get_version() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let key = vec![42u8; 32];

        let mut vault = SecretVault::new(KeySource::Bytes(key), &vault_path, None).unwrap();

        vault.set("test", b"value1").unwrap();
        vault.set("test", b"value2").unwrap();
        vault.set("test", b"value3").unwrap();

        let v1 = vault.get_version("test", 1).unwrap().unwrap();
        let v2 = vault.get_version("test", 2).unwrap().unwrap();
        let v3 = vault.get_version("test", 3).unwrap().unwrap();

        assert_eq!(v1, b"value1");
        assert_eq!(v2, b"value2");
        assert_eq!(v3, b"value3");
    }

    #[test]
    fn test_list_keys() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let key = vec![42u8; 32];

        let mut vault = SecretVault::new(KeySource::Bytes(key), &vault_path, None).unwrap();

        vault.set("key1", b"value1").unwrap();
        vault.set("key2", b"value2").unwrap();
        vault.set("key3", b"value3").unwrap();

        let mut keys = vault.list_keys();
        keys.sort();

        assert_eq!(keys, vec!["key1", "key2", "key3"]);
    }
}
