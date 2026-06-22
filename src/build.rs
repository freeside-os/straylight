use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PackageManifest {
    pub package: PackageInfo,
    #[serde(default)]
    pub sources: Vec<SourceInfo>,
    #[serde(default)]
    pub build: BuildInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BinaryPackageManifest {
    pub package: PackageInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub dependencies: Vec<String>, // Runtime dependencies
    pub group: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChecksumInfo {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceInfo {
    pub url: Option<String>,
    pub file: Option<String>,
    pub git: Option<String>,
    pub checksum: Option<ChecksumInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BuildInfo {
    #[serde(default)]
    pub dependencies: Vec<String>, // Build-time compile dependencies
    #[serde(alias = "environment")]
    pub env: Option<HashMap<String, toml::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileLedgerEntry {
    path: String,
    sha256: String,
    size: u64,
    mode: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FilesLedger {
    files: Vec<FileLedgerEntry>,
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}


fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file for hashing {:?}: {}", path, e))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("Failed to compute hash for {:?}: {}", path, e))?;
    Ok(format!("{:x}", hasher.finalize()))
}


fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst)
        .map_err(|e| format!("Failed to create target copy dir {:?}: {}", dst, e))?;
    for entry in fs::read_dir(src).map_err(|e| format!("Failed to read dir {:?}: {}", src, e))? {
        let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
        let path = entry.path();
        let ty = entry
            .file_type()
            .map_err(|e| format!("Failed to get file type: {}", e))?;

        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&path, &dest_path)?;
        } else if ty.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| format!("Failed to read link: {}", e))?;
            std::os::unix::fs::symlink(target, &dest_path)
                .map_err(|e| format!("Failed to create symlink: {}", e))?;
        } else {
            fs::copy(&path, &dest_path)
                .map_err(|e| format!("Failed to copy file {:?} to {:?}: {}", path, dest_path, e))?;
        }
    }
    Ok(())
}

fn traverse_staging(
    current_dir: &Path,
    staging_root: &Path,
    entries: &mut Vec<FileLedgerEntry>,
) -> Result<(), String> {
    for entry in fs::read_dir(current_dir)
        .map_err(|e| format!("Failed to read dir {:?}: {}", current_dir, e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();

        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to get symlink metadata for {:?}: {}", path, e))?;

        if metadata.is_dir() {
            if path.parent() == Some(staging_root) && entry.file_name() == "meta" {
                continue;
            }
            traverse_staging(&path, staging_root, entries)?;
        } else if metadata.is_file() {
            let rel_path = path
                .strip_prefix(staging_root)
                .map_err(|e| format!("Failed to strip prefix for {:?}: {}", path, e))?;
            let path_str = format!("./{}", rel_path.to_string_lossy());

            let sha256 = compute_file_sha256(&path)?;
            let size = metadata.len();
            let mode = format!("{:04o}", metadata.mode() & 0o7777);
            let uid = metadata.uid();
            let gid = metadata.gid();

            entries.push(FileLedgerEntry {
                path: path_str,
                sha256,
                size,
                mode,
                uid,
                gid,
            });
        }
    }
    Ok(())
}

fn create_tar_gz(src_dir: &Path, dest_file: &Path) -> Result<(), String> {
    let file = File::create(dest_file)
        .map_err(|e| format!("Failed to create archive file {:?}: {}", dest_file, e))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(enc);

    for entry in fs::read_dir(src_dir).map_err(|e| format!("Failed to read staging dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read staging entry: {}", e))?;
        let path = entry.path();
        let name = entry.file_name();

        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to get symlink metadata for {:?}: {}", path, e))?;

        if metadata.is_dir() {
            builder
                .append_dir_all(&name, &path)
                .map_err(|e| format!("Failed to append directory {:?} to tar: {}", name, e))?;
        } else if metadata.is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|e| format!("Failed to read link target of {:?}: {}", path, e))?;

            let mut header = tar::Header::new_gnu();
            header.set_metadata_in_mode(&metadata, tar::HeaderMode::Complete);
            header.set_entry_type(tar::EntryType::Symlink);
            builder
                .append_link(&mut header, &name, &target)
                .map_err(|e| format!("Failed to append symlink {:?} to tar: {}", name, e))?;
        } else {
            let mut file =
                File::open(&path).map_err(|e| format!("Failed to open file {:?}: {}", path, e))?;
            let mut header = tar::Header::new_gnu();
            header.set_metadata_in_mode(&metadata, tar::HeaderMode::Complete);
            header.set_size(metadata.len());
            builder
                .append_data(&mut header, &name, &mut file)
                .map_err(|e| format!("Failed to append file {:?} to tar: {}", name, e))?;
        }
    }

    builder
        .finish()
        .map_err(|e| format!("Failed to finish tar archive: {}", e))?;
    Ok(())
}

fn has_compiled_tarball(pkg_name: &str, builder_output_root: &Path) -> Result<bool, String> {
    if pkg_name == "musl" {
        return Ok(true);
    }
    if !builder_output_root.exists() {
        return Ok(false);
    }
    let prefix = format!("{}-", pkg_name);
    for entry in fs::read_dir(builder_output_root).map_err(|e| format!("Failed to read output dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix) && name_str.ends_with(".tar.gz") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn load_package_manifest(packages_root: &Path, pkg_name: &str) -> Result<PackageManifest, String> {
    let manifest_path = packages_root.join(pkg_name).join("package.manifest");
    if !manifest_path.exists() {
        return Err(format!("Manifest file not found for dependency '{}' at {:?}", pkg_name, manifest_path));
    }
    let content = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest for '{}': {}", pkg_name, e))?;
    let manifest: PackageManifest = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse manifest for '{}': {}", pkg_name, e))?;
    Ok(manifest)
}

fn collect_dependencies_rec(
    pkg_name: &str,
    packages_root: &Path,
    visited: &mut std::collections::HashSet<String>,
    order: &mut Vec<String>,
    temp_visited: &mut std::collections::HashSet<String>,
) -> Result<(), String> {
    if temp_visited.contains(pkg_name) {
        return Err(format!("Dependency cycle detected at '{}'", pkg_name));
    }
    if visited.contains(pkg_name) {
        return Ok(());
    }

    temp_visited.insert(pkg_name.to_string());

    let manifest = load_package_manifest(packages_root, pkg_name)?;
    
    // Merge runtime and build dependencies
    let mut deps = Vec::new();
    for dep in &manifest.package.dependencies {
        if dep != "musl" && !deps.contains(dep) {
            deps.push(dep.clone());
        }
    }
    for dep in &manifest.build.dependencies {
        if dep != "musl" && !deps.contains(dep) {
            deps.push(dep.clone());
        }
    }

    // Sort dependencies by name for determinism
    deps.sort();

    for dep in deps {
        collect_dependencies_rec(&dep, packages_root, visited, order, temp_visited)?;
    }

    temp_visited.remove(pkg_name);
    visited.insert(pkg_name.to_string());
    order.push(pkg_name.to_string());

    Ok(())
}

fn resolve_build_order(pkg_name: &str, packages_root: &Path) -> Result<Vec<String>, String> {
    let mut visited = std::collections::HashSet::new();
    let mut order = Vec::new();
    let mut temp_visited = std::collections::HashSet::new();
    collect_dependencies_rec(pkg_name, packages_root, &mut visited, &mut order, &mut temp_visited)?;
    Ok(order)
}

fn extract_dependency(dep_name: &str, builder_output_root: &Path, sandbox_dir: &Path) -> Result<(), String> {
    if dep_name == "musl" {
        return Ok(());
    }
    if !builder_output_root.exists() {
        return Ok(());
    }
    let mut candidates = Vec::new();
    let prefix = format!("{}-", dep_name);
    for entry in fs::read_dir(builder_output_root).map_err(|e| format!("Failed to read output dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix) && name_str.ends_with(".tar.gz") {
            candidates.push(entry.path());
        }
    }
    if candidates.is_empty() {
        println!("  Dependency '{}' tarball not found in builder output root, skipping auto-extract", dep_name);
        return Ok(());
    }
    // Sort to pick the newest by mtime
    candidates.sort_by(|a, b| {
        let ma = fs::metadata(a).and_then(|m| m.modified()).ok();
        let mb = fs::metadata(b).and_then(|m| m.modified()).ok();
        mb.cmp(&ma)
    });
    let tarball = &candidates[0];
    println!("  Auto-extracting dependency '{}' from {:?}", dep_name, tarball);
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("--exclude=meta")
        .arg("--exclude=./meta")
        .arg("-C")
        .arg(sandbox_dir)
        .status()
        .map_err(|e| format!("Failed to run tar command: {}", e))?;
    if !status.success() {
        return Err(format!("Failed to extract dependency '{}' tarball", dep_name));
    }
    Ok(())
}

pub fn build_package(package_name: &str, keep_sandbox: bool) -> Result<(), String> {
    // Phase 0: Check privileges and environments
    if !is_root() {
        return Err("Unauthorized: 'straylight build' requires root/sudo privileges to run systemd-nspawn sandboxes.".to_string());
    }

    let packages_dir = std::env::var("STRAYLIGHT_PACKAGES_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_PACKAGES_ROOT environment variable must be set".to_string())?;

    let builder_root = std::env::var("STRAYLIGHT_BUILDER_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_BUILDER_ROOT environment variable must be set".to_string())?;

    let builder_output_root = std::env::var("STRAYLIGHT_BUILDER_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_BUILDER_OUTPUT_ROOT environment variable must be set".to_string())?;

    // Phase 0.5: Resolve and Initialize Sandbox
    let sandbox_tarball = builder_root.join("sandbox-root.tgz");
    let sandbox_dir = builder_root.join("sandbox");

    if !sandbox_dir.exists() {
        if sandbox_tarball.exists() {
            println!("Sandbox directory not found. Extracting from {:?}...", sandbox_tarball);
            fs::create_dir_all(&sandbox_dir)
                .map_err(|e| format!("Failed to create sandbox directory {:?}: {}", sandbox_dir, e))?;
            let status = Command::new("tar")
                .arg("-xzf")
                .arg(&sandbox_tarball)
                .arg("-C")
                .arg(&sandbox_dir)
                .status()
                .map_err(|e| format!("Failed to extract sandbox tarball: {}", e))?;
            if !status.success() {
                return Err(format!("Failed to extract sandbox tarball (exit code: {:?})", status.code()));
            }
            println!("Sandbox extracted successfully to {:?}", sandbox_dir);
        } else {
            return Err(format!(
                "Builder sandbox not found. Expected sandbox at {:?} or tarball at {:?}.\n\
                 Run 'just build-sandbox' in the bootstrap/ directory first.",
                sandbox_dir, sandbox_tarball
            ));
        }
    }

    // Ensure dynamic linker and libgcc_s.so.1 are present
    {
        let lib_dir = sandbox_dir.join("lib");
        let ld_musl_src = sandbox_dir.join("usr/lib/ld-musl-x86_64.so.1");
        let ld_musl_dst = lib_dir.join("ld-musl-x86_64.so.1");
        if lib_dir.is_dir() && ld_musl_src.exists() && !ld_musl_dst.exists() {
            #[cfg(unix)]
            std::os::unix::fs::symlink("../usr/lib/ld-musl-x86_64.so.1", &ld_musl_dst)
                .map_err(|e| format!("Failed to create ld-musl symlink inside sandbox: {}", e))?;
        }

        let libgcc_sandbox = sandbox_dir.join("usr/lib/libgcc_s.so.1");
        if !libgcc_sandbox.exists() {
            let local_libgcc = builder_root.join("libgcc_s.so.1");
            if local_libgcc.exists() {
                std::fs::copy(&local_libgcc, &libgcc_sandbox)
                    .map_err(|e| format!("Failed to copy local libgcc_s.so.1 to sandbox: {}", e))?;
            } else {
                for path in &["/usr/lib/libgcc_s.so.1", "/lib/libgcc_s.so.1", "/lib/x86_64-linux-gnu/libgcc_s.so.1"] {
                    let p = std::path::Path::new(path);
                    if p.exists() {
                        std::fs::copy(p, &libgcc_sandbox)
                            .map_err(|e| format!("Failed to copy host libgcc_s.so.1 to sandbox: {}", e))?;
                        break;
                    }
                }
            }
        }

        // Also ensure find is present in the sandbox's usr/bin
        let find_sandbox = sandbox_dir.join("usr/bin/find");
        if !find_sandbox.exists() {
            let local_find = builder_root.join("find");
            if local_find.exists() {
                std::fs::copy(&local_find, &find_sandbox)
                    .map_err(|e| format!("Failed to copy local find to sandbox: {}", e))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&find_sandbox) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o755);
                        let _ = std::fs::set_permissions(&find_sandbox, perms);
                    }
                }
            }
        }
    }

    // Enforce UsrMerge symlinks in the sandbox
    let usr_sbin = sandbox_dir.join("usr/sbin");
    if usr_sbin.exists() && !usr_sbin.is_symlink() {
        println!("  Enforcing UsrMerge: Merging sandbox usr/sbin into usr/bin...");
        let usr_bin = sandbox_dir.join("usr/bin");
        for entry in fs::read_dir(&usr_sbin).map_err(|e| format!("Failed to read usr/sbin: {}", e))? {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let dest = usr_bin.join(entry.file_name());
            let _ = fs::remove_file(&dest); // overwrite if exists
            fs::copy(entry.path(), &dest)
                .map_err(|e| format!("Failed to copy file {:?} to {:?}: {}", entry.path(), dest, e))?;
        }
        fs::remove_dir_all(&usr_sbin).map_err(|e| format!("Failed to remove usr/sbin: {}", e))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("bin", &usr_sbin)
            .map_err(|e| format!("Failed to create usr/sbin symlink: {}", e))?;
    }

    // Delete any existing tarball for the target package in builder_output_root to force rebuild
    if builder_output_root.exists() {
        let prefix = format!("{}-", package_name);
        if let Ok(entries) = fs::read_dir(&builder_output_root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with(&prefix) && name_str.ends_with(".tar.gz") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    let mut cmd = build_nspawn_command(
        &sandbox_dir,
        &packages_dir,
        &builder_root,
        &builder_output_root,
        package_name,
        keep_sandbox,
    );

    println!("Spawning systemd-nspawn build for package '{}'...", package_name);
    let status = cmd.status()
        .map_err(|e| format!("Failed to run systemd-nspawn command: {}", e))?;

    if !status.success() {
        return Err(format!(
            "Sandbox package build exited with non-zero status: {:?}",
            status.code()
        ));
    }

    Ok(())
}

pub fn build_group(group_name: &str, keep_sandbox: bool) -> Result<(), String> {
    if !is_root() {
        return Err("Unauthorized: 'straylight build' requires root/sudo privileges to run systemd-nspawn sandboxes.".to_string());
    }

    let packages_dir = std::env::var("STRAYLIGHT_PACKAGES_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_PACKAGES_ROOT environment variable must be set".to_string())?;

    let builder_root = std::env::var("STRAYLIGHT_BUILDER_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_BUILDER_ROOT environment variable must be set".to_string())?;

    let builder_output_root = std::env::var("STRAYLIGHT_BUILDER_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map_err(|_| "STRAYLIGHT_BUILDER_OUTPUT_ROOT environment variable must be set".to_string())?;

    let sandbox_tarball = builder_root.join("sandbox-root.tgz");
    let sandbox_dir = builder_root.join("sandbox");

    if !sandbox_dir.exists() {
        if sandbox_tarball.exists() {
            println!("Sandbox directory not found. Extracting from {:?}...", sandbox_tarball);
            fs::create_dir_all(&sandbox_dir)
                .map_err(|e| format!("Failed to create sandbox directory {:?}: {}", sandbox_dir, e))?;
            let status = Command::new("tar")
                .arg("-xzf")
                .arg(&sandbox_tarball)
                .arg("-C")
                .arg(&sandbox_dir)
                .status()
                .map_err(|e| format!("Failed to extract sandbox tarball: {}", e))?;
            if !status.success() {
                return Err(format!("Failed to extract sandbox tarball (exit code: {:?})", status.code()));
            }
            println!("Sandbox extracted successfully to {:?}", sandbox_dir);
        } else {
            return Err(format!(
                "Builder sandbox not found. Expected sandbox at {:?} or tarball at {:?}.\n\
                 Run 'just build-sandbox' in the bootstrap/ directory first.",
                sandbox_dir, sandbox_tarball
            ));
        }
    }

    // Ensure dynamic linker and libgcc_s.so.1 are present (same as build_package)
    {
        let lib_dir = sandbox_dir.join("lib");
        let ld_musl_src = sandbox_dir.join("usr/lib/ld-musl-x86_64.so.1");
        let ld_musl_dst = lib_dir.join("ld-musl-x86_64.so.1");
        if lib_dir.is_dir() && ld_musl_src.exists() && !ld_musl_dst.exists() {
            #[cfg(unix)]
            std::os::unix::fs::symlink("../usr/lib/ld-musl-x86_64.so.1", &ld_musl_dst)
                .map_err(|e| format!("Failed to create ld-musl symlink inside sandbox: {}", e))?;
        }

        let libgcc_sandbox = sandbox_dir.join("usr/lib/libgcc_s.so.1");
        if !libgcc_sandbox.exists() {
            let local_libgcc = builder_root.join("libgcc_s.so.1");
            if local_libgcc.exists() {
                std::fs::copy(&local_libgcc, &libgcc_sandbox)
                    .map_err(|e| format!("Failed to copy local libgcc_s.so.1 to sandbox: {}", e))?;
            } else {
                for path in &["/usr/lib/libgcc_s.so.1", "/lib/libgcc_s.so.1", "/lib/x86_64-linux-gnu/libgcc_s.so.1"] {
                    let p = std::path::Path::new(path);
                    if p.exists() {
                        std::fs::copy(p, &libgcc_sandbox)
                            .map_err(|e| format!("Failed to copy host libgcc_s.so.1 to sandbox: {}", e))?;
                        break;
                    }
                }
            }
        }
    }

    let mut cmd = build_group_nspawn_command(
        &sandbox_dir,
        &packages_dir,
        &builder_root,
        &builder_output_root,
        group_name,
        keep_sandbox,
    );

    println!("Spawning systemd-nspawn group build for '{}'...", group_name);
    let status = cmd.status()
        .map_err(|e| format!("Failed to run systemd-nspawn command: {}", e))?;

    if !status.success() {
        return Err(format!(
            "Sandbox group build exited with non-zero status: {:?}",
            status.code()
        ));
    }

    Ok(())
}

fn build_nspawn_command(
    sandbox_dir: &Path,
    packages_dir: &Path,
    builder_root: &Path,
    builder_output_root: &Path,
    package_name: &str,
    keep_sandbox: bool,
) -> Command {
    let mut cmd = Command::new("systemd-nspawn");
    cmd.arg("-D").arg(sandbox_dir)
       .arg("--bind").arg(format!("{}:/workspace/packages", packages_dir.to_string_lossy()))
       .arg("--bind").arg(format!("{}:/workspace/build", builder_root.to_string_lossy()))
       .arg("--bind").arg(format!("{}:/workspace/packages_output", builder_output_root.to_string_lossy()))
       .arg("--as-pid2")
       .arg("--register=no");

    // Pass environment variables into the container using --setenv
    cmd.arg("--setenv=STRAYLIGHT_PACKAGES_ROOT=/workspace/packages");
    cmd.arg("--setenv=STRAYLIGHT_BUILDER_ROOT=/workspace/build");
    cmd.arg("--setenv=STRAYLIGHT_BUILDER_OUTPUT_ROOT=/workspace/packages_output");

    // Spawn the fspack.py build --pkg command inside the container
    cmd.arg("/usr/bin/python3")
       .arg("/workspace/packages/fspack.py")
       .arg("build")
       .arg("--pkg")
       .arg(package_name)
       .arg("--with-deps");
    if keep_sandbox {
        cmd.arg("--keep-sandbox");
    }
    cmd
}

fn build_group_nspawn_command(
    sandbox_dir: &Path,
    packages_dir: &Path,
    builder_root: &Path,
    builder_output_root: &Path,
    group_name: &str,
    keep_sandbox: bool,
) -> Command {
    let mut cmd = Command::new("systemd-nspawn");
    cmd.arg("-D").arg(sandbox_dir)
       .arg("--bind").arg(format!("{}:/workspace/packages", packages_dir.to_string_lossy()))
       .arg("--bind").arg(format!("{}:/workspace/build", builder_root.to_string_lossy()))
       .arg("--bind").arg(format!("{}:/workspace/packages_output", builder_output_root.to_string_lossy()))
       .arg("--as-pid2")
       .arg("--register=no");

    // Pass environment variables into the container using --setenv
    cmd.arg("--setenv=STRAYLIGHT_PACKAGES_ROOT=/workspace/packages");
    cmd.arg("--setenv=STRAYLIGHT_BUILDER_ROOT=/workspace/build");
    cmd.arg("--setenv=STRAYLIGHT_BUILDER_OUTPUT_ROOT=/workspace/packages_output");

    // Spawn the fspack.py build --group command inside the container
    cmd.arg("/usr/bin/python3")
       .arg("/workspace/packages/fspack.py")
       .arg("build")
       .arg("--group")
       .arg(group_name);
    if keep_sandbox {
        cmd.arg("--keep-sandbox");
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCleanup {
        path: PathBuf,
    }

    impl Drop for TestCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_temp_test_dir(name: &str) -> (PathBuf, TestCleanup) {
        let mut path = std::env::temp_dir();
        path.push(format!("straylight_test_{}_{}_{}", name, std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        let cleanup = TestCleanup { path: path.clone() };
        (path, cleanup)
    }

    #[test]
    fn test_has_compiled_tarball() {
        let (path, _cleanup) = create_temp_test_dir("has_compiled_tarball");
        
        // No tarballs
        assert!(!has_compiled_tarball("foo", &path).unwrap());
        
        // Write a matching tarball
        fs::write(path.join("foo-1.0.0-1.tar.gz"), b"").unwrap();
        assert!(has_compiled_tarball("foo", &path).unwrap());
        
        // Write a non-matching tarball
        assert!(!has_compiled_tarball("bar", &path).unwrap());
        
        // musl should always return true
        assert!(has_compiled_tarball("musl", &path).unwrap());
    }

    #[test]
    fn test_load_package_manifest() {
        let (path, _cleanup) = create_temp_test_dir("load_package_manifest");
        
        let pkg_dir = path.join("foo");
        fs::create_dir_all(&pkg_dir).unwrap();
        
        let manifest_content = r#"
[package]
name = "foo"
version = "1.0.0"
description = "test package"
dependencies = ["bar"]
group = "system"

[build]
dependencies = ["baz"]
"#;
        fs::write(pkg_dir.join("package.manifest"), manifest_content).unwrap();
        
        let manifest = load_package_manifest(&path, "foo").unwrap();
        assert_eq!(manifest.package.name, "foo");
        assert_eq!(manifest.package.version, "1.0.0");
        assert_eq!(manifest.package.dependencies, vec!["bar".to_string()]);
        assert_eq!(manifest.build.dependencies, vec!["baz".to_string()]);
    }

    #[test]
    fn test_resolve_build_order() {
        let (path, _cleanup) = create_temp_test_dir("resolve_build_order");
        
        let create_pkg = |name: &str, deps: &[&str], build_deps: &[&str]| {
            let pkg_dir = path.join(name);
            fs::create_dir_all(&pkg_dir).unwrap();
            let dep_strs: Vec<String> = deps.iter().map(|s| format!("\"{}\"", s)).collect();
            let build_dep_strs: Vec<String> = build_deps.iter().map(|s| format!("\"{}\"", s)).collect();
            let content = format!(
                r#"
[package]
name = "{}"
version = "1.0.0"
description = "test"
dependencies = [{}]

[build]
dependencies = [{}]
"#,
                name,
                dep_strs.join(", "),
                build_dep_strs.join(", ")
            );
            fs::write(pkg_dir.join("package.manifest"), content).unwrap();
        };

        create_pkg("foo", &["bar"], &[]);
        create_pkg("bar", &[], &["baz"]);
        create_pkg("baz", &[], &[]);
        
        let order = resolve_build_order("foo", &path).unwrap();
        assert_eq!(order, vec!["baz".to_string(), "bar".to_string(), "foo".to_string()]);
    }

    #[test]
    fn test_resolve_build_order_cycle() {
        let (path, _cleanup) = create_temp_test_dir("resolve_build_order_cycle");
        
        let create_pkg = |name: &str, deps: &[&str]| {
            let pkg_dir = path.join(name);
            fs::create_dir_all(&pkg_dir).unwrap();
            let dep_strs: Vec<String> = deps.iter().map(|s| format!("\"{}\"", s)).collect();
            let content = format!(
                r#"
[package]
name = "{}"
version = "1.0.0"
description = "test"
dependencies = [{}]

[build]
"#,
                name,
                dep_strs.join(", ")
            );
            fs::write(pkg_dir.join("package.manifest"), content).unwrap();
        };

        create_pkg("foo", &["bar"]);
        create_pkg("bar", &["foo"]);
        
        let res = resolve_build_order("foo", &path);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("cycle"));
    }

    #[test]
    fn test_build_nspawn_command() {
        let sandbox_dir = Path::new("/tmp/sandbox");
        let packages_dir = Path::new("/tmp/packages");
        let builder_root = Path::new("/tmp/build");
        let builder_output_root = Path::new("/tmp/packages_output");
        let package_name = "test-pkg";

        let cmd = build_nspawn_command(
            sandbox_dir,
            packages_dir,
            builder_root,
            builder_output_root,
            package_name,
            false,
        );

        assert_eq!(cmd.get_program(), "systemd-nspawn");

        let args: Vec<String> = cmd.get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        // Check sandbox dir argument
        assert!(args.contains(&"-D".to_string()));
        let d_idx = args.iter().position(|r| r == "-D").unwrap();
        assert_eq!(args[d_idx + 1], "/tmp/sandbox");

        // Check binds
        assert!(args.contains(&"--bind".to_string()));
        assert!(args.contains(&"/tmp/packages:/workspace/packages".to_string()));
        assert!(args.contains(&"/tmp/build:/workspace/build".to_string()));
        assert!(args.contains(&"/tmp/packages_output:/workspace/packages_output".to_string()));

        assert!(args.contains(&"--register=no".to_string()));

        // Check fspack call
        assert!(args.contains(&"/usr/bin/python3".to_string()));
        assert!(args.contains(&"/workspace/packages/fspack.py".to_string()));
        assert!(args.contains(&"build".to_string()));
        assert!(args.contains(&"--pkg".to_string()));
        assert!(args.contains(&"test-pkg".to_string()));
        assert!(args.contains(&"--with-deps".to_string()));
        assert!(!args.contains(&"--keep-sandbox".to_string()));

        // Test with keep_sandbox = true
        let cmd_keep = build_nspawn_command(
            sandbox_dir,
            packages_dir,
            builder_root,
            builder_output_root,
            package_name,
            true,
        );
        let args_keep: Vec<String> = cmd_keep.get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args_keep.contains(&"--keep-sandbox".to_string()));
    }

    #[test]
    fn test_build_group_nspawn_command() {
        let sandbox_dir = Path::new("/tmp/sandbox");
        let packages_dir = Path::new("/tmp/packages");
        let builder_root = Path::new("/tmp/build");
        let builder_output_root = Path::new("/tmp/packages_output");
        let group_name = "test-group";

        let cmd = build_group_nspawn_command(
            sandbox_dir,
            packages_dir,
            builder_root,
            builder_output_root,
            group_name,
            false,
        );

        assert_eq!(cmd.get_program(), "systemd-nspawn");

        let args: Vec<String> = cmd.get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        // Check sandbox dir argument
        assert!(args.contains(&"-D".to_string()));
        let d_idx = args.iter().position(|r| r == "-D").unwrap();
        assert_eq!(args[d_idx + 1], "/tmp/sandbox");

        // Check binds
        assert!(args.contains(&"--bind".to_string()));
        assert!(args.contains(&"/tmp/packages:/workspace/packages".to_string()));
        assert!(args.contains(&"/tmp/build:/workspace/build".to_string()));
        assert!(args.contains(&"/tmp/packages_output:/workspace/packages_output".to_string()));

        assert!(args.contains(&"--register=no".to_string()));

        // Check fspack call
        assert!(args.contains(&"/usr/bin/python3".to_string()));
        assert!(args.contains(&"/workspace/packages/fspack.py".to_string()));
        assert!(args.contains(&"build".to_string()));
        assert!(args.contains(&"--group".to_string()));
        assert!(args.contains(&"test-group".to_string()));
        assert!(!args.contains(&"--keep-sandbox".to_string()));

        // Test with keep_sandbox = true
        let cmd_keep = build_group_nspawn_command(
            sandbox_dir,
            packages_dir,
            builder_root,
            builder_output_root,
            group_name,
            true,
        );
        let args_keep: Vec<String> = cmd_keep.get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args_keep.contains(&"--keep-sandbox".to_string()));
    }
}

