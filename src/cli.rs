use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "A secure secrets vault for mobile backends", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to the vault file
    #[arg(short, long, default_value = "vault.yaml")]
    pub vault_path: PathBuf,

    /// Path to the master key file
    #[arg(long)]
    pub key_path: Option<PathBuf>,

    /// Environment variable containing the master key
    #[arg(long)]
    pub key_env: Option<String>,

    /// Path to the audit log file
    #[arg(long)]
    pub audit_path: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault and generate a master key
    Init {
        /// Output path for the generated master key
        #[arg(long)]
        key_out: Option<PathBuf>,
    },
    /// Set a secret
    Set {
        key: String,
        value: String,
    },
    /// Get a secret
    Get {
        key: String,
    },
    /// Delete a secret
    Delete {
        key: String,
    },
    /// Rotate the master key
    Rotate {
        /// Path to the new master key file (optional, otherwise generates new)
        #[arg(long)]
        new_key_path: Option<PathBuf>,
        /// Output path for the new master key if generated
        #[arg(long)]
        new_key_out: Option<PathBuf>,
    },
    /// List versions of a secret
    ListVersions {
        key: String,
    },
}
