use crate::error::{Result, VaultError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

/// Encrypts data using AES-256-GCM.
///
/// # Arguments
/// * `key` - A 32-byte encryption key
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// A vector containing the nonce (12 bytes) followed by the ciphertext.
///
/// # Errors
/// Returns `VaultError::InvalidKeySize` if the key is not 32 bytes.
/// Returns `VaultError::EncryptionFailed` if encryption fails.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(VaultError::InvalidKeySize {
            expected: KEY_SIZE,
            found: key.len(),
        });
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data using AES-256-GCM.
///
/// # Arguments
/// * `key` - A 32-byte encryption key
/// * `encrypted_data` - Data containing the nonce (12 bytes) followed by the ciphertext
///
/// # Returns
/// The decrypted plaintext.
///
/// # Errors
/// Returns `VaultError::InvalidKeySize` if the key is not 32 bytes.
/// Returns `VaultError::InvalidDataFormat` if the data is too short.
/// Returns `VaultError::DecryptionFailed` if decryption fails.
pub fn decrypt(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(VaultError::InvalidKeySize {
            expected: KEY_SIZE,
            found: key.len(),
        });
    }

    if encrypted_data.len() < NONCE_SIZE {
        return Err(VaultError::InvalidDataFormat(format!(
            "Data too short: {} bytes (minimum {} bytes required)",
            encrypted_data.len(),
            NONCE_SIZE
        )));
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
    let ciphertext = &encrypted_data[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let plaintext = b"Hello, world!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        assert_ne!(&encrypted[NONCE_SIZE..], plaintext);

        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_size() {
        let key = [42u8; 31];
        let plaintext = b"Hello";
        let result = encrypt(&key, plaintext);
        assert!(matches!(result, Err(VaultError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_invalid_data_format() {
        let key = [42u8; 32];
        let short_data = vec![0u8; 5];
        let result = decrypt(&key, &short_data);
        assert!(matches!(result, Err(VaultError::InvalidDataFormat(_))));
    }

    #[test]
    fn test_wrong_key_decryption() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let plaintext = b"Secret message";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);
        assert!(matches!(result, Err(VaultError::DecryptionFailed(_))));
    }
}
