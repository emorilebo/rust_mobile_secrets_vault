use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub enum Operation {
    Set,
    Get,
    Delete,
    Rotate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub operation: Operation,
    pub key: String,
}

pub struct AuditLogger {
    log_path: Option<std::path::PathBuf>,
}

impl AuditLogger {
    pub fn new(log_path: Option<&Path>) -> Self {
        Self {
            log_path: log_path.map(|p| p.to_path_buf()),
        }
    }

    pub fn log(&self, operation: Operation, key: &str) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            operation,
            key: key.to_string(),
        };

        if let Some(path) = &self.log_path {
            let log_line = serde_json::to_string(&entry)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            writeln!(file, "{}", log_line)?;
        }

        Ok(())
    }
}
