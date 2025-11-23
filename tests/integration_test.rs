use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_cli_flow() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let vault_path = temp_dir.path().join("vault.yaml");
    let key_path = temp_dir.path().join("master.key");
    let new_key_path = temp_dir.path().join("new_master.key");

    let mut cmd = Command::cargo_bin("vault")?;

    // 1. Init
    cmd.arg("init")
        .arg("--vault-path")
        .arg(&vault_path)
        .arg("--key-out")
        .arg(&key_path)
        .assert()
        .success();

    assert!(vault_path.exists());
    assert!(key_path.exists());

    // 2. Set Secret
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("set")
        .arg("my_secret")
        .arg("secret_value")
        .arg("--vault-path")
        .arg(&vault_path)
        .arg("--key-path")
        .arg(&key_path)
        .assert()
        .success();

    // 3. Get Secret
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("get")
        .arg("my_secret")
        .arg("--vault-path")
        .arg(&vault_path)
        .arg("--key-path")
        .arg(&key_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_value"));

    // 4. Rotate Key
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("rotate")
        .arg("--vault-path")
        .arg(&vault_path)
        .arg("--key-path")
        .arg(&key_path)
        .arg("--new-key-out")
        .arg(&new_key_path)
        .assert()
        .success();

    assert!(new_key_path.exists());

    // 5. Get Secret with New Key
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("get")
        .arg("my_secret")
        .arg("--vault-path")
        .arg(&vault_path)
        .arg("--key-path")
        .arg(&new_key_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_value"));

    Ok(())
}
