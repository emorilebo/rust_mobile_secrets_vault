# Publishing rust_mobile_secrets_vault to crates.io

## Pre-Publishing Checklist

- [ ] All tests pass: `cargo test`
- [ ] No clippy warnings: `cargo clippy -- -D warnings`
- [ ] Code is formatted: `cargo fmt --check`
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] Examples compile: `cargo build --examples`
- [ ] Dry run succeeds: `cargo publish --dry-run`

## Step-by-Step Publishing Guide

### 1. Login to crates.io

```bash
cargo login <your-api-token>
```

Get your API token from https://crates.io/me

### 2. Verify Package Metadata

Ensure `Cargo.toml` has:
- Correct version number
- Valid description
- Repository URL
- License
- README path

### 3. Run Tests

```bash
cargo test --all-features
```

All tests must pass before publishing.

### 4. Check Documentation

```bash
cargo doc --no-deps --open
```

Review the generated documentation for clarity.

### 5. Dry Run

```bash
cargo publish --dry-run
```

This verifies the package without uploading.

### 6. Publish

```bash
cargo publish
```

This uploads your crate to crates.io. **This action cannot be undone!**

### 7. Tag the Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 8. Verify on crates.io

Visit https://crates.io/crates/rust_mobile_secrets_vault to confirm.

## Post-Publishing

### Create GitHub Release

1. Go to your repository's releases page
2. Click "Draft a new release"
3. Select the tag you just created
4. Add release notes highlighting:
   - New features
   - Bug fixes
   - Breaking changes (if any)
   - Migration guide (if needed)

### Announce

- Share on social media
- Post to relevant Rust forums/Discord channels
- Update related documentation

## Versioning Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (0.1.X): Bug fixes, no API changes
- **Minor** (0.X.0): New features, backward compatible
- **Major** (X.0.0): Breaking changes

## Common Issues

### "Not all files included"
- Check `.gitignore` and `Cargo.toml` `exclude` field
- Ensure all necessary files are tracked by git

### "Payload too large"
- Verify `target/` directory is in `.gitignore`
- Check `exclude` in `Cargo.toml`

### "crate name already taken"
- Choose a different, unique name
- Check https://crates.io for availability

## Support

If you encounter issues:
- Check https://doc.rust-lang.org/cargo/reference/publishing.html
- Ask on https://users.rust-lang.org/
- Report bugs at your repository's issues page
