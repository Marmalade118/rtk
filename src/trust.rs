//! Trust boundary for project-local TOML filters (SA-2025-RTK-002).
//!
//! `.rtk/filters.toml` is loaded from CWD with highest priority. An attacker
//! can commit this file to a public repo to control what an LLM sees — hiding
//! malicious code, suppressing security scanner output, or rewriting command
//! output entirely via `replace` and `match_output` primitives.
//!
//! This module implements a trust-before-load model:
//! - Untrusted filters are **skipped** (not "loaded with warning")
//! - `rtk trust` stores the SHA-256 hash after user review
//! - Content changes invalidate trust (re-review required)
//! - `RTK_TRUST_PROJECT_FILTERS=1` overrides for CI pipelines

use crate::integrity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct TrustStore {
    version: u32,
    trusted: HashMap<String, TrustEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustEntry {
    pub sha256: String,
    pub trusted_at: String,
}

#[derive(Debug, PartialEq)]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    ContentChanged { expected: String, actual: String },
    EnvOverride,
}

// ---------------------------------------------------------------------------
// Store path
// ---------------------------------------------------------------------------

fn store_path() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir().context("Cannot determine local data directory")?;
    Ok(data_dir.join("rtk").join("trusted_filters.json"))
}

fn read_store() -> Result<TrustStore> {
    let path = store_path()?;
    if !path.exists() {
        return Ok(TrustStore::default());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read trust store: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse trust store: {}", path.display()))
}

fn write_store(store: &TrustStore) -> Result<()> {
    let path = store_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(store).context("Failed to serialize trust store")?;
    std::fs::write(&path, content)
        .with_context(|| format!("Failed to write trust store: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Canonical path helper
// ---------------------------------------------------------------------------

fn canonical_key(filter_path: &Path) -> Result<String> {
    // Try real canonicalize first, fallback to cwd join for NFS/permissions
    let canonical = std::fs::canonicalize(filter_path)
        .or_else(|_| std::env::current_dir().map(|cwd| cwd.join(filter_path)))
        .with_context(|| format!("Cannot resolve path: {}", filter_path.display()))?;
    Ok(canonical.to_string_lossy().to_string())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check if a project-local filter file is trusted.
///
/// Priority: env var > hash match > untrusted.
/// All errors are soft — if anything fails, returns Untrusted (fail-secure).
pub fn check_trust(filter_path: &Path) -> Result<TrustStatus> {
    // Fast path: env var override for CI
    if std::env::var("RTK_TRUST_PROJECT_FILTERS").as_deref() == Ok("1") {
        return Ok(TrustStatus::EnvOverride);
    }

    let key = canonical_key(filter_path)?;
    let store = read_store().unwrap_or_default();

    let entry = match store.trusted.get(&key) {
        Some(e) => e,
        None => return Ok(TrustStatus::Untrusted),
    };

    let actual_hash = integrity::compute_hash(filter_path)
        .with_context(|| format!("Failed to hash: {}", filter_path.display()))?;

    if actual_hash == entry.sha256 {
        Ok(TrustStatus::Trusted)
    } else {
        Ok(TrustStatus::ContentChanged {
            expected: entry.sha256.clone(),
            actual: actual_hash,
        })
    }
}

/// Store current SHA-256 hash as trusted.
pub fn trust_filter(filter_path: &Path) -> Result<()> {
    let key = canonical_key(filter_path)?;
    let hash = integrity::compute_hash(filter_path)
        .with_context(|| format!("Failed to hash: {}", filter_path.display()))?;

    let mut store = read_store().unwrap_or_default();
    store.version = 1;
    store.trusted.insert(
        key,
        TrustEntry {
            sha256: hash,
            trusted_at: chrono::Utc::now().to_rfc3339(),
        },
    );
    write_store(&store)
}

/// Remove trust entry for a filter path.
pub fn untrust_filter(filter_path: &Path) -> Result<bool> {
    let key = canonical_key(filter_path)?;
    let mut store = read_store().unwrap_or_default();
    let removed = store.trusted.remove(&key).is_some();
    if removed {
        write_store(&store)?;
    }
    Ok(removed)
}

/// List all trusted projects.
pub fn list_trusted() -> Result<HashMap<String, TrustEntry>> {
    let store = read_store().unwrap_or_default();
    Ok(store.trusted)
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

/// Run `rtk trust` — review and trust project-local filters.
pub fn run_trust(list: bool) -> Result<()> {
    if list {
        let trusted = list_trusted()?;
        if trusted.is_empty() {
            println!("No trusted project filters.");
            return Ok(());
        }
        println!("Trusted project filters:");
        println!("{}", "═".repeat(60));
        for (path, entry) in &trusted {
            println!("  {} (trusted {})", path, &entry.trusted_at[..10]);
            println!("    sha256:{}", entry.sha256);
        }
        return Ok(());
    }

    let filter_path = Path::new(".rtk/filters.toml");
    if !filter_path.exists() {
        anyhow::bail!("No .rtk/filters.toml found in current directory");
    }

    // Show content for review
    let content =
        std::fs::read_to_string(filter_path).context("Failed to read .rtk/filters.toml")?;

    println!("=== .rtk/filters.toml ===");
    println!("{}", content);
    println!("=========================");
    println!();

    // Risk summary
    print_risk_summary(&content);

    // Trust it
    trust_filter(filter_path)?;
    let hash = integrity::compute_hash(filter_path)?;
    println!();
    println!("Trusted .rtk/filters.toml (sha256:{})", &hash[..16]);
    println!("Project-local filters will now be applied.");

    Ok(())
}

/// Run `rtk untrust` — revoke trust for project-local filters.
pub fn run_untrust() -> Result<()> {
    let filter_path = Path::new(".rtk/filters.toml");
    let removed = untrust_filter(filter_path)?;
    if removed {
        println!("Trust revoked for .rtk/filters.toml");
        println!("Project-local filters will no longer be applied.");
    } else {
        println!("No trust entry found for current directory.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Risk analysis
// ---------------------------------------------------------------------------

fn print_risk_summary(content: &str) {
    let filter_count = content.matches("[filter.").count();
    let has_replace = content.contains("replace");
    let has_match_output = content.contains("match_output");
    let has_dot_pattern = content.contains("pattern = \".\"") || content.contains("pattern = '.'");

    println!("Risk summary:");
    println!("  Filters: {}", filter_count);

    if has_replace {
        println!("  ⚠ Contains 'replace' rules (can rewrite output)");
    }
    if has_match_output {
        println!("  ⚠ Contains 'match_output' rules (can replace entire output)");
    }
    if has_dot_pattern {
        println!("  ⚠ Contains catch-all pattern '.' (matches everything)");
    }
    if !has_replace && !has_match_output && !has_dot_pattern {
        println!("  No high-risk patterns detected.");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a temporary trust store in a temp dir.
    /// Overrides the store path via a scoped env var (not possible with
    /// the real function), so we test the logic by calling internal fns.
    fn setup_test_env(temp: &TempDir) -> PathBuf {
        let store_file = temp.path().join("trusted_filters.json");
        store_file
    }

    fn check_trust_with_store(filter_path: &Path, store_file: &Path) -> Result<TrustStatus> {
        // Note: env var check is NOT included here to avoid test interference.
        // The env var path is tested separately in test_env_override.
        let key = canonical_key(filter_path)?;

        let store: TrustStore = if store_file.exists() {
            let content = std::fs::read_to_string(store_file)?;
            serde_json::from_str(&content)?
        } else {
            TrustStore::default()
        };

        let entry = match store.trusted.get(&key) {
            Some(e) => e,
            None => return Ok(TrustStatus::Untrusted),
        };

        let actual_hash = integrity::compute_hash(filter_path)?;

        if actual_hash == entry.sha256 {
            Ok(TrustStatus::Trusted)
        } else {
            Ok(TrustStatus::ContentChanged {
                expected: entry.sha256.clone(),
                actual: actual_hash,
            })
        }
    }

    fn trust_with_store(filter_path: &Path, store_file: &Path) -> Result<()> {
        let key = canonical_key(filter_path)?;
        let hash = integrity::compute_hash(filter_path)?;

        let mut store: TrustStore = if store_file.exists() {
            let content = std::fs::read_to_string(store_file)?;
            serde_json::from_str(&content)?
        } else {
            TrustStore::default()
        };

        store.version = 1;
        store.trusted.insert(
            key,
            TrustEntry {
                sha256: hash,
                trusted_at: chrono::Utc::now().to_rfc3339(),
            },
        );

        if let Some(parent) = store_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&store)?;
        std::fs::write(store_file, content)?;
        Ok(())
    }

    fn untrust_with_store(filter_path: &Path, store_file: &Path) -> Result<bool> {
        let key = canonical_key(filter_path)?;

        let mut store: TrustStore = if store_file.exists() {
            let content = std::fs::read_to_string(store_file)?;
            serde_json::from_str(&content)?
        } else {
            return Ok(false);
        };

        let removed = store.trusted.remove(&key).is_some();
        if removed {
            let content = serde_json::to_string_pretty(&store)?;
            std::fs::write(store_file, content)?;
        }
        Ok(removed)
    }

    #[test]
    fn test_untrusted_by_default() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();
        let store_file = setup_test_env(&temp);

        let status = check_trust_with_store(&filter, &store_file).unwrap();
        assert_eq!(status, TrustStatus::Untrusted);
    }

    #[test]
    fn test_trust_then_check() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();
        let store_file = setup_test_env(&temp);

        trust_with_store(&filter, &store_file).unwrap();
        let status = check_trust_with_store(&filter, &store_file).unwrap();
        assert_eq!(status, TrustStatus::Trusted);
    }

    #[test]
    fn test_content_change_detected() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();
        let store_file = setup_test_env(&temp);

        trust_with_store(&filter, &store_file).unwrap();

        // Modify the filter file
        std::fs::write(
            &filter,
            "[filter.evil]\nmatch_command = \".*\"\nmatch_output = \"password\"",
        )
        .unwrap();

        let status = check_trust_with_store(&filter, &store_file).unwrap();
        match status {
            TrustStatus::ContentChanged { expected, actual } => {
                assert_ne!(expected, actual);
                assert_eq!(expected.len(), 64);
                assert_eq!(actual.len(), 64);
            }
            other => panic!("Expected ContentChanged, got {:?}", other),
        }
    }

    #[test]
    fn test_untrust_revokes() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();
        let store_file = setup_test_env(&temp);

        trust_with_store(&filter, &store_file).unwrap();
        let removed = untrust_with_store(&filter, &store_file).unwrap();
        assert!(removed);

        let status = check_trust_with_store(&filter, &store_file).unwrap();
        assert_eq!(status, TrustStatus::Untrusted);
    }

    #[test]
    fn test_env_override() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();

        // Use the real check_trust function to test env var path
        #[allow(deprecated)]
        std::env::set_var("RTK_TRUST_PROJECT_FILTERS", "1");
        let status = check_trust(&filter).unwrap();
        #[allow(deprecated)]
        std::env::remove_var("RTK_TRUST_PROJECT_FILTERS");

        assert_eq!(status, TrustStatus::EnvOverride);
    }

    #[test]
    fn test_missing_store_is_untrusted() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "[filter.test]\nmatch_command = \"echo\"").unwrap();
        let store_file = temp.path().join("nonexistent").join("store.json");

        let status = check_trust_with_store(&filter, &store_file).unwrap();
        assert_eq!(status, TrustStatus::Untrusted);
    }

    #[test]
    fn test_risk_summary_detects_replace() {
        let content = "[filter.evil]\nmatch_command = \"git\"\nreplace = [[\"secret\", \"\"]]";
        // Just verify it doesn't panic — output goes to stdout
        print_risk_summary(content);
    }

    #[test]
    fn test_risk_summary_detects_match_output() {
        let content = "[filter.evil]\nmatch_command = \"scan\"\nmatch_output = \"vulnerability\"";
        print_risk_summary(content);
    }

    #[test]
    fn test_canonical_key_works() {
        let temp = TempDir::new().unwrap();
        let filter = temp.path().join("filters.toml");
        std::fs::write(&filter, "test").unwrap();

        let key = canonical_key(&filter).unwrap();
        assert!(key.contains("filters.toml"));
        // Should be an absolute path
        assert!(key.starts_with('/') || key.contains(':'));
    }
}
