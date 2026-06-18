use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;

// ---------------------------------------------------------------------------
// Data Structures (files.toml schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,    // Relative path inside package (e.g., "./usr/bin/kitty")
    pub sha256: String,  // Hex representation of SHA256 hash
    pub size: u64,       // File size in bytes
    pub mode: String,    // UNIX file permissions (e.g., "0755" as octal string)
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilesManifest {
    pub files: Vec<FileRecord>,
}

// Reuse the binary manifest type from the build module's output
#[derive(Debug, Deserialize)]
struct BinaryPackageManifest {
    package: PackageInfo,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    name: String,
    version: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    dependencies: Vec<String>,
    #[allow(dead_code)]
    group: Option<String>,
}

// ---------------------------------------------------------------------------
// Package source resolution
// ---------------------------------------------------------------------------

/// Describes where the package tarball came from so we know whether to cache it.
#[derive(Debug)]
enum PackageSource {
    /// An external tarball path — needs to be copied into the cache.
    External(PathBuf),
    /// Already lives in the cache — skip the copy step.
    Cached(PathBuf),
}

/// Given the raw CLI argument, determine if it's a tarball file path or a
/// `<name>-<version>` cache reference, and resolve to a concrete tarball path.
///
/// Resolution order:
/// 1. If the argument looks like a file path (contains '/' or ends with '.tar.gz')
///    and that file exists on disk, treat it as an external tarball.
/// 2. Otherwise, treat it as a `<name>-<version>` cache reference and search
///    `STRAYLIGHT_PKG_CACHE_ROOT` for a matching `<name>-<version>-*.tar.gz`.
fn resolve_package_input(input: &str, cache_root: &Path) -> Result<PackageSource, String> {
    let as_path = Path::new(input);

    // Heuristic: if the argument contains a path separator or has .tar.gz
    // extension, try the filesystem first.
    if input.contains('/') || input.ends_with(".tar.gz") || input.ends_with(".tgz") {
        if as_path.exists() {
            // Check if this file already lives inside the cache directory
            if let (Ok(canonical_file), Ok(canonical_cache)) =
                (as_path.canonicalize(), cache_root.canonicalize())
            {
                if canonical_file.starts_with(&canonical_cache) {
                    return Ok(PackageSource::Cached(canonical_file));
                }
            }
            return Ok(PackageSource::External(as_path.to_path_buf()));
        }
        return Err(format!("Package tarball not found: {}", input));
    }

    // Not a file path — interpret as <name>-<version> cache reference.
    // Look for <cache_root>/<input>-*.tar.gz
    if !cache_root.exists() {
        return Err(format!(
            "Package '{}' not found: cache directory {:?} does not exist",
            input, cache_root
        ));
    }

    let prefix = format!("{}-", input);
    let mut candidates: Vec<PathBuf> = Vec::new();

    let entries = fs::read_dir(cache_root)
        .map_err(|e| format!("Failed to read cache directory {:?}: {}", cache_root, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read cache entry: {}", e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix) && name_str.ends_with(".tar.gz") {
            candidates.push(entry.path());
        }
    }

    match candidates.len() {
        0 => Err(format!(
            "Package '{}' not found in cache {:?}. \
             No files matching '{}-*.tar.gz' exist.",
            input, cache_root, input
        )),
        1 => Ok(PackageSource::Cached(candidates.remove(0))),
        _ => {
            // Multiple builds found — pick the most recent by filesystem mtime
            candidates.sort_by(|a, b| {
                let ma = fs::metadata(a).and_then(|m| m.modified()).ok();
                let mb = fs::metadata(b).and_then(|m| m.modified()).ok();
                mb.cmp(&ma) // descending — newest first
            });
            eprintln!(
                "  Note: {} cached builds found for '{}', using newest: {}",
                candidates.len(),
                input,
                candidates[0].file_name().unwrap_or_default().to_string_lossy()
            );
            Ok(PackageSource::Cached(candidates.remove(0)))
        }
    }
}

// ---------------------------------------------------------------------------
// Environment resolution helpers
// ---------------------------------------------------------------------------

fn resolve_rw_system_root() -> PathBuf {
    std::env::var("STRAYLIGHT_RW_SYSTEM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/straylight_staging_root"))
}

fn resolve_pkg_cache_root() -> PathBuf {
    std::env::var("STRAYLIGHT_PKG_CACHE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/cache/straylight/packages"))
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

fn compute_sha256_of_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file for hashing {:?}: {}", path, e))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("Failed to compute SHA256 for {:?}: {}", path, e))?;
    Ok(format!("{:x}", hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Tarball in-memory extraction helpers
// ---------------------------------------------------------------------------

/// Extract a single file from a .tar.gz archive by its exact entry path.
/// Returns the file content as bytes, or None if the entry was not found.
fn extract_entry_from_tarball(tarball_path: &Path, entry_path: &str) -> Result<Option<Vec<u8>>, String> {
    let file = File::open(tarball_path)
        .map_err(|e| format!("Failed to open tarball {:?}: {}", tarball_path, e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let entries = archive.entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry_result in entries {
        let mut entry = entry_result
            .map_err(|e| format!("Failed to read tarball entry: {}", e))?;

        let path = entry.path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_path_buf();

        let path_str = path.to_string_lossy();
        // Match both "meta/files.toml" and "./meta/files.toml" variants
        let normalized = path_str.strip_prefix("./").unwrap_or(&path_str);
        if normalized == entry_path {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read entry {}: {}", entry_path, e))?;
            return Ok(Some(buf));
        }
    }

    Ok(None)
}

/// Extract a specific file from a .tar.gz archive and write it to a destination path.
/// Writes atomically (temp file + rename) to prevent corruption on interruption.
fn extract_file_to_dest(tarball_path: &Path, entry_path: &str, dest_path: &Path) -> Result<(), String> {
    let file = File::open(tarball_path)
        .map_err(|e| format!("Failed to open tarball {:?}: {}", tarball_path, e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let entries = archive.entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry_result in entries {
        let mut entry = entry_result
            .map_err(|e| format!("Failed to read tarball entry: {}", e))?;

        let path = entry.path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_path_buf();

        let path_str = path.to_string_lossy();
        let normalized = path_str.strip_prefix("./").unwrap_or(&path_str);
        if normalized == entry_path {
            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create parent dirs for {:?}: {}", dest_path, e))?;
            }

            // Atomic write: write to temp file, then rename
            let tmp_path = dest_path.with_extension("straylight_tmp");
            {
                let mut tmp_file = File::create(&tmp_path)
                    .map_err(|e| format!("Failed to create temp file {:?}: {}", tmp_path, e))?;
                io::copy(&mut entry, &mut tmp_file)
                    .map_err(|e| format!("Failed to write to temp file {:?}: {}", tmp_path, e))?;
                tmp_file.flush()
                    .map_err(|e| format!("Failed to flush temp file {:?}: {}", tmp_path, e))?;
            }

            fs::rename(&tmp_path, dest_path)
                .map_err(|e| format!("Failed to rename {:?} -> {:?}: {}", tmp_path, dest_path, e))?;

            return Ok(());
        }
    }

    Err(format!("Entry '{}' not found in tarball {:?}", entry_path, tarball_path))
}

/// List all executable hook scripts inside `meta/hooks/` from the tarball.
fn list_hook_entries(tarball_path: &Path) -> Result<Vec<String>, String> {
    let file = File::open(tarball_path)
        .map_err(|e| format!("Failed to open tarball {:?}: {}", tarball_path, e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let mut hooks = Vec::new();
    let entries = archive.entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry_result in entries {
        let entry = entry_result
            .map_err(|e| format!("Failed to read tarball entry: {}", e))?;

        let path = entry.path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_path_buf();

        let path_str = path.to_string_lossy().to_string();
        let normalized = path_str.strip_prefix("./").unwrap_or(&path_str).to_string();

        if normalized.starts_with("meta/hooks/") && !entry.header().entry_type().is_dir() {
            hooks.push(normalized);
        }
    }

    // Sort for deterministic execution order
    hooks.sort();
    Ok(hooks)
}

// ---------------------------------------------------------------------------
// Build ID extraction
// ---------------------------------------------------------------------------

/// Extract the build ID from a tarball filename given the package name and version.
/// Falls back to "1" if the filename doesn't match the expected pattern.
fn extract_build_id(tarball_path: &Path, pkg_name: &str, pkg_version: &str) -> String {
    tarball_path
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| {
            let expected_prefix = format!("{}-{}-", pkg_name, pkg_version);
            if s.starts_with(&expected_prefix) {
                let rest = &s[expected_prefix.len()..];
                let rest = rest.strip_suffix(".tar").unwrap_or(rest);
                Some(rest.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "1".to_string())
}

// ---------------------------------------------------------------------------
// Permissions / ownership application
// ---------------------------------------------------------------------------

fn apply_file_metadata(path: &Path, record: &FileRecord) -> Result<(), String> {
    // Apply permissions (mode)
    let mode = u32::from_str_radix(&record.mode, 8)
        .map_err(|e| format!("Invalid mode '{}' for {:?}: {}", record.mode, path, e))?;
    fs::set_permissions(path, Permissions::from_mode(mode))
        .map_err(|e| format!("Failed to set permissions on {:?}: {}", path, e))?;

    // Apply uid/gid ownership via libc chown
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| format!("Failed to create CString for chown on {:?}: {}", path, e))?;

    let ret = unsafe {
        libc::chown(c_path.as_ptr(), record.uid, record.gid)
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // Non-fatal: chown may fail without root privileges during development
        eprintln!(
            "  Warning: chown({}, {}:{}) failed for {:?}: {} (continuing)",
            record.uid, record.gid, path.display(), path.display(), err
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Diff engine: compare existing file against declared state
// ---------------------------------------------------------------------------

enum FileStatus {
    Missing,
    Changed(Vec<&'static str>),
    Identical,
}

fn check_file_status(dest_path: &Path, record: &FileRecord) -> Result<FileStatus, String> {
    if !dest_path.exists() {
        return Ok(FileStatus::Missing);
    }

    let metadata = fs::metadata(dest_path)
        .map_err(|e| format!("Failed to stat {:?}: {}", dest_path, e))?;

    let mut reasons = Vec::new();

    // Check size
    if metadata.len() != record.size {
        reasons.push("size");
    }

    // Check mode
    let current_mode = format!("{:04o}", metadata.mode() & 0o7777);
    if current_mode != record.mode {
        reasons.push("mode");
    }

    // Check uid/gid
    if metadata.uid() != record.uid {
        reasons.push("uid");
    }
    if metadata.gid() != record.gid {
        reasons.push("gid");
    }

    // Check SHA256 (most expensive, do last and only if size matched)
    if !reasons.contains(&"size") {
        let current_hash = compute_sha256_of_file(dest_path)?;
        if current_hash != record.sha256 {
            reasons.push("sha256");
        }
    } else {
        // Size already differs, checksum will certainly differ too
        reasons.push("sha256");
    }

    if reasons.is_empty() {
        Ok(FileStatus::Identical)
    } else {
        Ok(FileStatus::Changed(reasons))
    }
}

// ---------------------------------------------------------------------------
// packages.toml registration
// ---------------------------------------------------------------------------

fn register_package(
    config_path: &Path,
    pkg_name: &str,
    cached_path: &str,
    version: &str,
) -> Result<(), String> {
    // Ensure parent directories exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory {:?}: {}", parent, e))?;
    }

    // Read existing config or start from empty
    let existing_content = if config_path.exists() {
        fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read {:?}: {}", config_path, e))?
    } else {
        String::new()
    };

    // Parse existing TOML as a generic table to preserve all sections
    let mut doc: toml::value::Table = if existing_content.is_empty() {
        toml::value::Table::new()
    } else {
        toml::from_str(&existing_content)
            .map_err(|e| format!("Failed to parse {:?}: {}", config_path, e))?
    };

    // Ensure [packages] section exists
    if !doc.contains_key("packages") {
        doc.insert("packages".to_string(), toml::Value::Table(toml::value::Table::new()));
    }

    let packages = doc.get_mut("packages")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| "Failed to access [packages] section".to_string())?;

    // Ensure [packages.local] section exists
    if !packages.contains_key("local") {
        packages.insert("local".to_string(), toml::Value::Table(toml::value::Table::new()));
    }

    let local = packages.get_mut("local")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| "Failed to access [packages.local] section".to_string())?;

    // Build the entry inline table: { path = "...", version = "..." }
    let mut entry = toml::value::Table::new();
    entry.insert("path".to_string(), toml::Value::String(cached_path.to_string()));
    entry.insert("version".to_string(), toml::Value::String(version.to_string()));

    local.insert(pkg_name.to_string(), toml::Value::Table(entry));

    // Serialize back to TOML
    let output = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize packages.toml: {}", e))?;

    // Atomic write
    let tmp_path = config_path.with_extension("straylight_tmp");
    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temp config {:?}: {}", tmp_path, e))?;
        f.write_all(output.as_bytes())
            .map_err(|e| format!("Failed to write temp config {:?}: {}", tmp_path, e))?;
        f.flush()
            .map_err(|e| format!("Failed to flush temp config {:?}: {}", tmp_path, e))?;
    }
    fs::rename(&tmp_path, config_path)
        .map_err(|e| format!("Failed to rename config {:?} -> {:?}: {}", tmp_path, config_path, e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry point: install_package
// ---------------------------------------------------------------------------

pub fn install_package(input: &str) -> Result<(), String> {
    let rw_system_root = resolve_rw_system_root();
    let pkg_cache_root = resolve_pkg_cache_root();
    install_package_impl(input, &rw_system_root, &pkg_cache_root)
}

/// Internal implementation that accepts explicit paths, enabling direct
/// testing without environment variable mutation.
fn install_package_impl(
    input: &str,
    rw_system_root: &Path,
    pkg_cache_root: &Path,
) -> Result<(), String> {

    // ── Resolve the package source ───────────────────────────────────────
    let source = resolve_package_input(input, &pkg_cache_root)?;

    let (tarball_path, from_cache) = match &source {
        PackageSource::External(p) => (p.clone(), false),
        PackageSource::Cached(p) => (p.clone(), true),
    };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          straylight install-pkg — Local Package Engine       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    if from_cache {
        println!("  Source:       {} (from cache)", tarball_path.display());
    } else {
        println!("  Source:       {}", tarball_path.display());
    }
    println!("  Staging Root: {}", rw_system_root.display());
    println!("  Cache Root:   {}", pkg_cache_root.display());
    println!();

    // ── Phase 1: Package Integrity Verification ──────────────────────────
    println!("── Phase 1: Package Integrity Verification ──");

    let files_toml_bytes = extract_entry_from_tarball(&tarball_path, "meta/files.toml")?
        .ok_or_else(|| "Package integrity failure: meta/files.toml not found in tarball".to_string())?;

    let pkg_manifest_bytes = extract_entry_from_tarball(&tarball_path, "meta/package.manifest")?
        .ok_or_else(|| "Package integrity failure: meta/package.manifest not found in tarball".to_string())?;

    let files_toml_str = String::from_utf8(files_toml_bytes)
        .map_err(|e| format!("meta/files.toml is not valid UTF-8: {}", e))?;
    let pkg_manifest_str = String::from_utf8(pkg_manifest_bytes)
        .map_err(|e| format!("meta/package.manifest is not valid UTF-8: {}", e))?;

    let files_manifest: FilesManifest = toml::from_str(&files_toml_str)
        .map_err(|e| format!("Failed to parse meta/files.toml: {}", e))?;
    let pkg_manifest: BinaryPackageManifest = toml::from_str(&pkg_manifest_str)
        .map_err(|e| format!("Failed to parse meta/package.manifest: {}", e))?;

    let pkg_name = &pkg_manifest.package.name;
    let pkg_version = &pkg_manifest.package.version;

    println!("  ✓ Package:     {} v{}", pkg_name, pkg_version);
    println!("  ✓ File ledger: {} entries parsed", files_manifest.files.len());
    println!();

    // ── Phase 2: Cache the Package (Arch-Style) ──────────────────────────
    // Skip this phase entirely when installing from cache — tarball is
    // already where it needs to be.
    let cached_path = if from_cache {
        println!("── Phase 2: Cache Package to Local Store ──");
        println!("  ✓ Already cached: {}", tarball_path.display());
        println!();
        tarball_path.clone()
    } else {
        println!("── Phase 2: Cache Package to Local Store ──");

        fs::create_dir_all(&pkg_cache_root)
            .map_err(|e| format!("Failed to create cache directory {:?}: {}", pkg_cache_root, e))?;

        let build_id = extract_build_id(&tarball_path, pkg_name, pkg_version);
        let cached_filename = format!("{}-{}-{}.tar.gz", pkg_name, pkg_version, build_id);
        let dest = pkg_cache_root.join(&cached_filename);

        fs::copy(&tarball_path, &dest)
            .map_err(|e| format!("Failed to cache package to {:?}: {}", dest, e))?;

        println!("  ✓ Cached: {}", dest.display());
        println!();
        dest
    };

    // ── Phase 3: Register in Staging Root's packages.toml ────────────────
    println!("── Phase 3: Register Package in Staging Ledger ──");

    let config_path = Path::new(&rw_system_root).join("etc/freeside/packages.toml");

    register_package(
        &config_path,
        pkg_name,
        &cached_path.to_string_lossy(),
        pkg_version,
    )?;

    println!("  ✓ Registered [packages.local].{} in {}", pkg_name, config_path.display());
    println!();

    // ── Phase 4: Differential File Copy Engine ───────────────────────────
    println!("── Phase 4: Differential File Copy ──");

    let mut stats_skipped: u64 = 0;
    let mut stats_updated: u64 = 0;
    let mut stats_created: u64 = 0;

    for record in &files_manifest.files {
        let rel_path = record.path.strip_prefix("./").unwrap_or(&record.path);
        let dest_path = Path::new(&rw_system_root).join(rel_path);

        match check_file_status(&dest_path, record)? {
            FileStatus::Identical => {
                stats_skipped += 1;
            }
            FileStatus::Missing => {
                // Ensure parent directory hierarchy exists
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create dirs for {:?}: {}", dest_path, e))?;
                }

                // Extract this specific file from the tarball
                extract_file_to_dest(&tarball_path, rel_path, &dest_path)?;
                apply_file_metadata(&dest_path, record)?;

                println!("  + created: {}", rel_path);
                stats_created += 1;
            }
            FileStatus::Changed(reasons) => {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create dirs for {:?}: {}", dest_path, e))?;
                }

                extract_file_to_dest(&tarball_path, rel_path, &dest_path)?;
                apply_file_metadata(&dest_path, record)?;

                println!("  ~ updated: {} ({})", rel_path, reasons.join(", "));
                stats_updated += 1;
            }
        }
    }

    println!();
    println!("  Summary: {} created, {} updated, {} skipped (identical)",
             stats_created, stats_updated, stats_skipped);
    println!();

    // ── Phase 4b: Hook Execution ─────────────────────────────────────────
    let hooks = list_hook_entries(&tarball_path)?;
    if !hooks.is_empty() {
        println!("── Phase 4b: Executing Package Hooks ──");

        // Extract hooks to a temporary directory within the staging root
        let hooks_tmp_dir = Path::new(&rw_system_root).join(".straylight_hooks_tmp");
        fs::create_dir_all(&hooks_tmp_dir)
            .map_err(|e| format!("Failed to create hooks tmp dir: {}", e))?;

        for hook_entry in &hooks {
            let hook_name = Path::new(hook_entry)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| hook_entry.clone());

            let hook_dest = hooks_tmp_dir.join(&hook_name);

            // Extract the hook script
            let hook_bytes = extract_entry_from_tarball(&tarball_path, hook_entry)?
                .ok_or_else(|| format!("Hook entry '{}' not found in tarball", hook_entry))?;

            fs::write(&hook_dest, &hook_bytes)
                .map_err(|e| format!("Failed to write hook {:?}: {}", hook_dest, e))?;

            // Make executable
            fs::set_permissions(&hook_dest, Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to chmod hook {:?}: {}", hook_dest, e))?;

            println!("  → Running hook: {}", hook_name);

            let output = Command::new(&hook_dest)
                .env("STRAYLIGHT_RW_SYSTEM_ROOT", &rw_system_root)
                .env("PKG_NAME", pkg_name)
                .env("PKG_VERSION", pkg_version)
                .output()
                .map_err(|e| format!("Failed to execute hook '{}': {}", hook_name, e))?;

            if !output.stdout.is_empty() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    println!("    │ {}", line);
                }
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("  ⚠ Hook '{}' exited with status {:?}", hook_name, output.status.code());
                if !stderr.is_empty() {
                    for line in stderr.lines() {
                        eprintln!("    │ {}", line);
                    }
                }
            } else {
                println!("    ✓ Hook '{}' completed successfully", hook_name);
            }
        }

        // Clean up temporary hooks directory
        let _ = fs::remove_dir_all(&hooks_tmp_dir);
        println!();
    }

    // ── Done ─────────────────────────────────────────────────────────────
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  ✓ Package {} v{} installed successfully", pkg_name, pkg_version);
    println!("║    {} files processed ({} new, {} updated, {} unchanged)",
             stats_created + stats_updated + stats_skipped,
             stats_created, stats_updated, stats_skipped);
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::os::unix::fs::PermissionsExt;

    // ── Test helpers ─────────────────────────────────────────────────────

    /// Create a unique temporary directory under the workspace for test isolation.
    fn make_test_dir(name: &str) -> PathBuf {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test_tmp");
        let dir = base.join(format!("{}_{}", name, std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("cleanup old test dir");
        }
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    /// Build a minimal valid package tarball in memory and write it to `dest`.
    /// Returns the SHA256 hex hash and size of the single payload file.
    fn create_test_tarball(
        dest: &Path,
        pkg_name: &str,
        pkg_version: &str,
        file_content: &[u8],
    ) -> (String, u64) {
        let file_hash = {
            let mut h = Sha256::new();
            h.update(file_content);
            format!("{:x}", h.finalize())
        };

        let manifest = format!(
            "[package]\nname = \"{}\"\nversion = \"{}\"\n\
             description = \"test package\"\ndependencies = []\n",
            pkg_name, pkg_version
        );
        let files_toml = format!(
            "[[files]]\npath = \"./usr/bin/hello\"\nsha256 = \"{}\"\n\
             size = {}\nmode = \"0755\"\nuid = {}\ngid = {}\n",
            file_hash,
            file_content.len(),
            // Use current user's uid/gid so chown won't fail in tests
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );

        let out_file = File::create(dest).expect("create tarball");
        let enc = GzEncoder::new(out_file, Compression::fast());
        let mut builder = tar::Builder::new(enc);

        // Add meta/package.manifest
        let manifest_bytes = manifest.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "meta/package.manifest", manifest_bytes)
            .expect("append manifest");

        // Add meta/files.toml
        let files_bytes = files_toml.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(files_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "meta/files.toml", files_bytes)
            .expect("append files.toml");

        // Add the payload file
        let mut header = tar::Header::new_gnu();
        header.set_size(file_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/bin/hello", file_content)
            .expect("append payload");

        builder.finish().expect("finish tarball");
        (file_hash, file_content.len() as u64)
    }

    /// Build a tarball with a hook script inside meta/hooks/.
    fn create_test_tarball_with_hooks(
        dest: &Path,
        pkg_name: &str,
        pkg_version: &str,
        file_content: &[u8],
        hook_script: &[u8],
    ) -> (String, u64) {
        let file_hash = {
            let mut h = Sha256::new();
            h.update(file_content);
            format!("{:x}", h.finalize())
        };

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let manifest = format!(
            "[package]\nname = \"{}\"\nversion = \"{}\"\n\
             description = \"test package\"\ndependencies = []\n",
            pkg_name, pkg_version
        );
        let files_toml = format!(
            "[[files]]\npath = \"./usr/bin/hello\"\nsha256 = \"{}\"\n\
             size = {}\nmode = \"0755\"\nuid = {}\ngid = {}\n",
            file_hash, file_content.len(), uid, gid,
        );

        let out_file = File::create(dest).expect("create tarball");
        let enc = GzEncoder::new(out_file, Compression::fast());
        let mut builder = tar::Builder::new(enc);

        let mut h = tar::Header::new_gnu();
        let b = manifest.as_bytes();
        h.set_size(b.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append_data(&mut h, "meta/package.manifest", b).unwrap();

        let mut h = tar::Header::new_gnu();
        let b = files_toml.as_bytes();
        h.set_size(b.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append_data(&mut h, "meta/files.toml", b).unwrap();

        let mut h = tar::Header::new_gnu();
        h.set_size(file_content.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        builder.append_data(&mut h, "usr/bin/hello", file_content).unwrap();

        let mut h = tar::Header::new_gnu();
        h.set_size(hook_script.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        builder.append_data(&mut h, "meta/hooks/post-install", hook_script).unwrap();

        builder.finish().expect("finish tarball");
        (file_hash, file_content.len() as u64)
    }

    // ── SHA256 Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_compute_sha256_of_file() {
        let dir = make_test_dir("sha256");
        let file_path = dir.join("sample.txt");
        fs::write(&file_path, b"hello world\n").unwrap();

        let hash = compute_sha256_of_file(&file_path).unwrap();
        // Known SHA256 of "hello world\n"
        assert_eq!(
            hash,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let dir = make_test_dir("sha256_empty");
        let file_path = dir.join("empty.txt");
        fs::write(&file_path, b"").unwrap();

        let hash = compute_sha256_of_file(&file_path).unwrap();
        // Known SHA256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_compute_sha256_nonexistent_file() {
        let result = compute_sha256_of_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    // ── Build ID Extraction Tests ────────────────────────────────────────

    #[test]
    fn test_extract_build_id_standard() {
        let path = Path::new("build/packages/zlib-1.3.1-1.tar.gz");
        assert_eq!(extract_build_id(path, "zlib", "1.3.1"), "1");
    }

    #[test]
    fn test_extract_build_id_custom() {
        let path = Path::new("/cache/kitty-0.35.2-42.tar.gz");
        assert_eq!(extract_build_id(path, "kitty", "0.35.2"), "42");
    }

    #[test]
    fn test_extract_build_id_fallback() {
        let path = Path::new("my-custom-package.tar.gz");
        assert_eq!(extract_build_id(path, "zlib", "1.3.1"), "1");
    }

    #[test]
    fn test_extract_build_id_mismatched_name() {
        let path = Path::new("other-pkg-2.0.0-5.tar.gz");
        assert_eq!(extract_build_id(path, "zlib", "1.3.1"), "1");
    }

    // ── Tarball Extraction Tests ─────────────────────────────────────────

    #[test]
    fn test_extract_entry_from_tarball_found() {
        let dir = make_test_dir("extract_entry");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "test", "1.0.0", b"#!/bin/sh\necho hi\n");

        let result = extract_entry_from_tarball(&tarball, "meta/files.toml").unwrap();
        assert!(result.is_some());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("[[files]]"));
        assert!(content.contains("usr/bin/hello"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_extract_entry_from_tarball_not_found() {
        let dir = make_test_dir("extract_missing");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "test", "1.0.0", b"content");

        let result = extract_entry_from_tarball(&tarball, "nonexistent/file.txt").unwrap();
        assert!(result.is_none());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_extract_entry_manifest() {
        let dir = make_test_dir("extract_manifest");
        let tarball = dir.join("hello-2.0.0-1.tar.gz");
        create_test_tarball(&tarball, "hello", "2.0.0", b"binary");

        let result = extract_entry_from_tarball(&tarball, "meta/package.manifest").unwrap();
        assert!(result.is_some());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("name = \"hello\""));
        assert!(content.contains("version = \"2.0.0\""));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_extract_file_to_dest() {
        let dir = make_test_dir("extract_to_dest");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "test", "1.0.0", b"#!/bin/sh\necho hello\n");

        let dest = dir.join("output/usr/bin/hello");
        extract_file_to_dest(&tarball, "usr/bin/hello", &dest).unwrap();

        assert!(dest.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"#!/bin/sh\necho hello\n");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_extract_file_to_dest_not_found() {
        let dir = make_test_dir("extract_dest_missing");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "test", "1.0.0", b"x");

        let result = extract_file_to_dest(&tarball, "nonexistent", &dir.join("out"));
        assert!(result.is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── Hook Listing Tests ───────────────────────────────────────────────

    #[test]
    fn test_list_hook_entries_none() {
        let dir = make_test_dir("hooks_none");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "test", "1.0.0", b"payload");

        let hooks = list_hook_entries(&tarball).unwrap();
        assert!(hooks.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_list_hook_entries_present() {
        let dir = make_test_dir("hooks_present");
        let tarball = dir.join("test-1.0.0-1.tar.gz");
        create_test_tarball_with_hooks(
            &tarball,
            "test",
            "1.0.0",
            b"payload",
            b"#!/bin/sh\necho hook\n",
        );

        let hooks = list_hook_entries(&tarball).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0], "meta/hooks/post-install");

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── File Status / Diff Engine Tests ──────────────────────────────────

    #[test]
    fn test_check_file_status_missing() {
        let record = FileRecord {
            path: "./usr/bin/nope".to_string(),
            sha256: "abc123".to_string(),
            size: 100,
            mode: "0755".to_string(),
            uid: 0,
            gid: 0,
        };
        match check_file_status(Path::new("/nonexistent/path"), &record).unwrap() {
            FileStatus::Missing => {} // expected
            _ => panic!("Expected FileStatus::Missing"),
        }
    }

    #[test]
    fn test_check_file_status_identical() {
        let dir = make_test_dir("status_identical");
        let file_path = dir.join("testfile");
        let content = b"identical content";
        fs::write(&file_path, content).unwrap();

        // Compute real hash
        let hash = compute_sha256_of_file(&file_path).unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let record = FileRecord {
            path: "./testfile".to_string(),
            sha256: hash,
            size: content.len() as u64,
            mode: format!("{:04o}", meta.mode() & 0o7777),
            uid: meta.uid(),
            gid: meta.gid(),
        };

        match check_file_status(&file_path, &record).unwrap() {
            FileStatus::Identical => {} // expected
            FileStatus::Changed(reasons) => panic!("Expected identical, got changed: {:?}", reasons),
            FileStatus::Missing => panic!("Expected identical, got missing"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_check_file_status_changed_size() {
        let dir = make_test_dir("status_size");
        let file_path = dir.join("testfile");
        fs::write(&file_path, b"short").unwrap();

        let meta = fs::metadata(&file_path).unwrap();
        let record = FileRecord {
            path: "./testfile".to_string(),
            sha256: "doesntmatter".to_string(),
            size: 99999, // different size
            mode: format!("{:04o}", meta.mode() & 0o7777),
            uid: meta.uid(),
            gid: meta.gid(),
        };

        match check_file_status(&file_path, &record).unwrap() {
            FileStatus::Changed(reasons) => {
                assert!(reasons.contains(&"size"));
                assert!(reasons.contains(&"sha256"));
            }
            _ => panic!("Expected FileStatus::Changed"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_check_file_status_changed_sha256() {
        let dir = make_test_dir("status_sha256");
        let file_path = dir.join("testfile");
        let content = b"some data";
        fs::write(&file_path, content).unwrap();

        let meta = fs::metadata(&file_path).unwrap();
        let record = FileRecord {
            path: "./testfile".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            size: content.len() as u64,
            mode: format!("{:04o}", meta.mode() & 0o7777),
            uid: meta.uid(),
            gid: meta.gid(),
        };

        match check_file_status(&file_path, &record).unwrap() {
            FileStatus::Changed(reasons) => {
                assert!(reasons.contains(&"sha256"));
                assert!(!reasons.contains(&"size"));
            }
            _ => panic!("Expected FileStatus::Changed with sha256 reason"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_check_file_status_changed_mode() {
        let dir = make_test_dir("status_mode");
        let file_path = dir.join("testfile");
        let content = b"mode test";
        fs::write(&file_path, content).unwrap();
        fs::set_permissions(&file_path, Permissions::from_mode(0o644)).unwrap();

        let hash = compute_sha256_of_file(&file_path).unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let record = FileRecord {
            path: "./testfile".to_string(),
            sha256: hash,
            size: content.len() as u64,
            mode: "0755".to_string(), // different from 0644
            uid: meta.uid(),
            gid: meta.gid(),
        };

        match check_file_status(&file_path, &record).unwrap() {
            FileStatus::Changed(reasons) => {
                assert!(reasons.contains(&"mode"));
            }
            _ => panic!("Expected FileStatus::Changed with mode reason"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── Package Registration Tests ───────────────────────────────────────

    #[test]
    fn test_register_package_new_file() {
        let dir = make_test_dir("register_new");
        let config = dir.join("etc/freeside/packages.toml");

        register_package(&config, "myapp", "/cache/myapp-1.0.0-1.tar.gz", "1.0.0")
            .unwrap();

        let content = fs::read_to_string(&config).unwrap();
        assert!(content.contains("[packages.local.myapp]"));
        assert!(content.contains("path = \"/cache/myapp-1.0.0-1.tar.gz\""));
        assert!(content.contains("version = \"1.0.0\""));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_register_package_append() {
        let dir = make_test_dir("register_append");
        let config = dir.join("etc/freeside/packages.toml");

        register_package(&config, "aaa", "/cache/aaa-1.0-1.tar.gz", "1.0").unwrap();
        register_package(&config, "bbb", "/cache/bbb-2.0-1.tar.gz", "2.0").unwrap();

        let content = fs::read_to_string(&config).unwrap();
        assert!(content.contains("[packages.local.aaa]"));
        assert!(content.contains("[packages.local.bbb]"));
        assert!(content.contains("version = \"1.0\""));
        assert!(content.contains("version = \"2.0\""));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_register_package_update_existing() {
        let dir = make_test_dir("register_update");
        let config = dir.join("etc/freeside/packages.toml");

        register_package(&config, "myapp", "/cache/myapp-1.0.0-1.tar.gz", "1.0.0")
            .unwrap();
        register_package(&config, "myapp", "/cache/myapp-2.0.0-1.tar.gz", "2.0.0")
            .unwrap();

        let content = fs::read_to_string(&config).unwrap();
        // Should have the updated version, not the old one
        assert!(content.contains("version = \"2.0.0\""));
        assert!(!content.contains("version = \"1.0.0\""));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_register_package_preserves_existing_sections() {
        let dir = make_test_dir("register_preserve");
        let config = dir.join("etc/freeside/packages.toml");

        // Write a pre-existing config with [system] section
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(
            &config,
            "[system]\nprofile = \"desktop\"\ntree = \"abc123\"\n\n[packages]\napps = [\"firefox\"]\n",
        )
        .unwrap();

        register_package(&config, "kitty", "/cache/kitty-0.35-1.tar.gz", "0.35")
            .unwrap();

        let content = fs::read_to_string(&config).unwrap();
        // Original sections must be preserved
        assert!(content.contains("profile = \"desktop\""));
        assert!(content.contains("tree = \"abc123\""));
        // New local section must exist
        assert!(content.contains("[packages.local.kitty]"));

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── Package Input Resolution Tests ───────────────────────────────────

    #[test]
    fn test_resolve_input_tarball_path() {
        let dir = make_test_dir("resolve_path");
        let tarball = dir.join("myapp-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "myapp", "1.0.0", b"x");

        let cache = dir.join("cache");
        fs::create_dir_all(&cache).unwrap();

        match resolve_package_input(tarball.to_str().unwrap(), &cache).unwrap() {
            PackageSource::External(p) => assert_eq!(p, tarball),
            PackageSource::Cached(_) => panic!("Expected External"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_resolve_input_nonexistent_path() {
        let cache = Path::new("/tmp/nonexistent_cache_dir_xyz");
        let result = resolve_package_input("/no/such/file.tar.gz", cache);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_input_cache_reference() {
        let dir = make_test_dir("resolve_cache_ref");
        let cache = dir.join("cache");
        fs::create_dir_all(&cache).unwrap();

        let tarball = cache.join("kitty-0.35.2-1.tar.gz");
        create_test_tarball(&tarball, "kitty", "0.35.2", b"meow");

        match resolve_package_input("kitty-0.35.2", &cache).unwrap() {
            PackageSource::Cached(p) => assert_eq!(p, tarball),
            PackageSource::External(_) => panic!("Expected Cached"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_resolve_input_cache_reference_not_found() {
        let dir = make_test_dir("resolve_cache_miss");
        let cache = dir.join("cache");
        fs::create_dir_all(&cache).unwrap();

        let result = resolve_package_input("nonexistent-1.0.0", &cache);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found in cache"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_resolve_input_path_inside_cache_detected() {
        let dir = make_test_dir("resolve_in_cache");
        let cache = dir.join("cache");
        fs::create_dir_all(&cache).unwrap();

        let tarball = cache.join("myapp-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "myapp", "1.0.0", b"data");

        // Pass the full path, but it's inside the cache — should be Cached
        match resolve_package_input(tarball.to_str().unwrap(), &cache).unwrap() {
            PackageSource::Cached(_) => {} // expected
            PackageSource::External(_) => panic!("Expected Cached for path inside cache dir"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── Full Pipeline Integration Test ───────────────────────────────────

    #[test]
    fn test_install_package_full_pipeline() {
        let dir = make_test_dir("full_pipeline");
        let staging = dir.join("staging");
        let cache = dir.join("cache");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&cache).unwrap();

        let tarball = dir.join("mypkg-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "mypkg", "1.0.0", b"#!/bin/sh\necho test\n");

        install_package_impl(tarball.to_str().unwrap(), &staging, &cache).unwrap();

        // Verify: payload file was extracted
        let installed = staging.join("usr/bin/hello");
        assert!(installed.exists(), "Payload file should be installed");
        assert_eq!(fs::read(&installed).unwrap(), b"#!/bin/sh\necho test\n");

        // Verify: package was cached
        let cached = cache.join("mypkg-1.0.0-1.tar.gz");
        assert!(cached.exists(), "Tarball should be in cache");

        // Verify: packages.toml was written
        let config = staging.join("etc/freeside/packages.toml");
        assert!(config.exists(), "packages.toml should be created");
        let config_content = fs::read_to_string(&config).unwrap();
        assert!(config_content.contains("[packages.local.mypkg]"));
        assert!(config_content.contains("version = \"1.0.0\""));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_package_from_cache_skips_copy() {
        let dir = make_test_dir("from_cache");
        let staging = dir.join("staging");
        let cache = dir.join("cache");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&cache).unwrap();

        // Place tarball directly in cache
        let tarball = cache.join("cached-pkg-2.0.0-1.tar.gz");
        create_test_tarball(&tarball, "cached-pkg", "2.0.0", b"cached binary");

        // Install via name reference (not path)
        install_package_impl("cached-pkg-2.0.0", &staging, &cache).unwrap();

        // Verify: payload installed
        let installed = staging.join("usr/bin/hello");
        assert!(installed.exists());
        assert_eq!(fs::read(&installed).unwrap(), b"cached binary");

        // Verify: no duplicate file was created in cache
        let cache_files: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(cache_files.len(), 1, "Should still be exactly one file in cache");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_package_idempotent() {
        let dir = make_test_dir("idempotent");
        let staging = dir.join("staging");
        let cache = dir.join("cache");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&cache).unwrap();

        let tarball = dir.join("idempkg-1.0.0-1.tar.gz");
        create_test_tarball(&tarball, "idempkg", "1.0.0", b"static content");

        // Install twice
        install_package_impl(tarball.to_str().unwrap(), &staging, &cache).unwrap();
        install_package_impl(tarball.to_str().unwrap(), &staging, &cache).unwrap();

        // Should still work — file is identical so it should be skipped
        let installed = staging.join("usr/bin/hello");
        assert!(installed.exists());
        assert_eq!(fs::read(&installed).unwrap(), b"static content");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_package_with_hooks() {
        let dir = make_test_dir("with_hooks");
        let staging = dir.join("staging");
        let cache = dir.join("cache");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&cache).unwrap();

        let hook_script = b"#!/bin/sh\ntouch \"$STRAYLIGHT_RW_SYSTEM_ROOT/hook_ran\"\n";
        let tarball = dir.join("hookpkg-1.0.0-1.tar.gz");
        create_test_tarball_with_hooks(
            &tarball,
            "hookpkg",
            "1.0.0",
            b"payload",
            hook_script,
        );

        install_package_impl(tarball.to_str().unwrap(), &staging, &cache).unwrap();

        // Verify: hook created the sentinel file
        let sentinel = staging.join("hook_ran");
        assert!(sentinel.exists(), "Hook should have created sentinel file");

        fs::remove_dir_all(&dir).unwrap();
    }

    // ── FilesManifest Parse Tests ────────────────────────────────────────

    #[test]
    fn test_files_manifest_parse() {
        let toml_str = r#"
[[files]]
path = "./usr/bin/kitty"
sha256 = "abc123"
size = 1024
mode = "0755"
uid = 0
gid = 0

[[files]]
path = "./usr/lib/libfoo.so"
sha256 = "def456"
size = 2048
mode = "0644"
uid = 0
gid = 0
"#;
        let manifest: FilesManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].path, "./usr/bin/kitty");
        assert_eq!(manifest.files[0].mode, "0755");
        assert_eq!(manifest.files[1].path, "./usr/lib/libfoo.so");
        assert_eq!(manifest.files[1].size, 2048);
    }

    #[test]
    fn test_files_manifest_parse_empty() {
        let toml_str = "files = []\n";
        let manifest: FilesManifest = toml::from_str(toml_str).unwrap();
        assert!(manifest.files.is_empty());
    }

    #[test]
    fn test_files_manifest_parse_invalid() {
        let toml_str = "this is not valid toml [[[";
        let result: Result<FilesManifest, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    // ── Apply Metadata Tests ─────────────────────────────────────────────

    #[test]
    fn test_apply_file_metadata_permissions() {
        let dir = make_test_dir("apply_meta");
        let file_path = dir.join("testbin");
        fs::write(&file_path, b"binary").unwrap();
        fs::set_permissions(&file_path, Permissions::from_mode(0o644)).unwrap();

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let record = FileRecord {
            path: "./testbin".to_string(),
            sha256: "unused".to_string(),
            size: 6,
            mode: "0755".to_string(),
            uid,
            gid,
        };

        apply_file_metadata(&file_path, &record).unwrap();

        let meta = fs::metadata(&file_path).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o755);

        fs::remove_dir_all(&dir).unwrap();
    }
}
