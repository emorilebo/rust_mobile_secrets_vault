pub mod audit;
pub mod encryption;
pub mod vault;
pub mod cli;

pub use audit::{AuditLogger, Operation};
pub use encryption::{encrypt, decrypt};
pub use vault::{KeySource, SecretVault, MasterKey};
