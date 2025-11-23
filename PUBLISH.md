# Publishing Instructions

1.  **Login to Crates.io**
    ```bash
    cargo login <your-token>
    ```

2.  **Verify Metadata**
    Ensure `Cargo.toml` has the correct version, description, and license.

3.  **Dry Run**
    ```bash
    cargo publish --dry-run
    ```

4.  **Publish**
    ```bash
    cargo publish
    ```

5.  **Tag Release**
    ```bash
    git tag v0.1.0
    git push origin v0.1.0
    ```
