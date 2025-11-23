use crate::audit::{AuditLogger, Operation};
use crate::encryption::{decrypt, encrypt, KEY_SIZE};
use anyhow::{Context, Result};
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
            return Err(anyhow::anyhow!("Invalid key size: expected {} bytes", KEY_SIZE));
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

pub struct SecretVault {
    master_key: MasterKey,
    path: PathBuf,
    data: VaultData,
    audit_logger: AuditLogger,
}

pub enum KeySource {
    Env(String),
    File(PathBuf),
    Bytes(Vec<u8>),
}

impl KeySource {
    pub fn load(self) -> Result<MasterKey> {
        let key_bytes = match self {
            KeySource::Env(var_name) => {
                let val = std::env::var(&var_name)
                    .context(format!("Environment variable {} not found", var_name))?;
                general_purpose::STANDARD
                    .decode(val)
                    .context("Failed to decode base64 key from env")?
            }
            KeySource::File(path) => {
                let content = fs::read_to_string(&path)
                    .context(format!("Failed to read key file {:?}", path))?;
                general_purpose::STANDARD
                    .decode(content.trim())
                    .context("Failed to decode base64 key from file")?
            }
            KeySource::Bytes(bytes) => bytes,
        };
        MasterKey::new(key_bytes)
    }
}

impl SecretVault {
    pub fn new(master_key: KeySource, path: &Path, audit_path: Option<&Path>) -> Result<Self> {
        let master_key = master_key.load()?;
        let data = if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            serde_yaml::from_reader(reader).context("Failed to parse vault file")?
        } else {
            VaultData::default()
        };

        Ok(Self {
            master_key,
            path: path.to_path_buf(),
            data,
            audit_logger: AuditLogger::new(audit_path),
        })
    }

    pub fn save(&self) -> Result<()> {
        let file = File::create(&self.path).context("Failed to create vault file")?;
        serde_yaml::to_writer(file, &self.data).context("Failed to write vault data")?;
        Ok(())
    }

    pub fn set(&mut self, key: &str, value: &[u8]) -> Result<()> {
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

    pub fn delete(&mut self, key: &str) -> Result<()> {
        if self.data.secrets.remove(key).is_some() {
            self.save()?;
            self.audit_logger.log(Operation::Delete, key)?;
        }
        Ok(())
    }

    pub fn list_versions(&self, key: &str) -> Result<Vec<u32>> {
        if let Some(entries) = self.data.secrets.get(key) {
            Ok(entries.iter().map(|e| e.version).collect())
        } else {
            Ok(vec![])
        }
    }

    pub fn rotate(&mut self, new_master_source: KeySource) -> Result<()> {
        let new_master_key = new_master_source.load()?;
        
        // Re-encrypt all secrets
        for (key, entries) in self.data.secrets.iter_mut() {
            for entry in entries.iter_mut() {
                let decrypted = decrypt(self.master_key.as_bytes(), &entry.encrypted_value)
                    .context(format!("Failed to decrypt secret {} during rotation", key))?;
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
