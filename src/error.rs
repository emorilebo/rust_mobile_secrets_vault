use std::fmt;

/// Custom error type for vault operations
#[derive(Debug)]
pub enum VaultError {
    /// Invalid key size
    InvalidKeySize { expected: usize, found: usize },
    /// Failed to encrypt data
    EncryptionFailed(String),
    /// Failed to decrypt data
    DecryptionFailed(String),
    /// Invalid encrypted data format
    InvalidDataFormat(String),
    /// I/O error
    Io(std::io::Error),
    /// Serialization error
    Serialization(String),
    /// Invalid secret key name
    InvalidSecretKey(String),
    /// Secret not found
    SecretNotFound(String),
    /// Key loading error
    KeyLoadError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::InvalidKeySize { expected, found } => {
                write!(
                    f,
                    "Invalid key size: expected {} bytes, found {} bytes",
                    expected, found
                )
            }
            VaultError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            VaultError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            VaultError::InvalidDataFormat(msg) => write!(f, "Invalid data format: {}", msg),
            VaultError::Io(err) => write!(f, "I/O error: {}", err),
            VaultError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            VaultError::InvalidSecretKey(key) => write!(f, "Invalid secret key: {}", key),
            VaultError::SecretNotFound(key) => write!(f, "Secret not found: {}", key),
            VaultError::KeyLoadError(msg) => write!(f, "Failed to load key: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::Io(err)
    }
}

impl From<serde_yaml::Error> for VaultError {
    fn from(err: serde_yaml::Error) -> Self {
        VaultError::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(err: serde_json::Error) -> Self {
        VaultError::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for VaultError {
    fn from(err: base64::DecodeError) -> Self {
        VaultError::KeyLoadError(format!("Base64 decode error: {}", err))
    }
}

/// Result type for vault operations
pub type Result<T> = std::result::Result<T, VaultError>;
