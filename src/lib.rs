pub mod audit;
pub mod cli;
pub mod encryption;
pub mod error;
pub mod vault;

pub use audit::{AuditLogger, Operation};
pub use encryption::{decrypt, encrypt};
pub use error::{Result, VaultError};
pub use vault::{KeySource, MasterKey, SecretVault};
