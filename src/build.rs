use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageManifest {
    pub package: PackageInfo,
    pub source: SourceInfo,
    pub build: BuildInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub dependencies: Vec<String>, // Runtime dependencies
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildInfo {
    pub dependencies: Vec<String>, // Build-time compile dependencies
    pub lto: Option<bool>,
    pub cflags: Option<Vec<String>>,
    pub ldflags: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
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

fn find_monorepo_root() -> Result<PathBuf, String> {
    let mut current =
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;
    loop {
        if current.join("justfile").exists() && current.join("docs").exists() {
            return Ok(current);
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return Err("Could not find monorepo root (searched for 'justfile' and 'docs' directories up the tree)".to_string());
        }
    }
}

fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file for hashing {:?}: {}", path, e))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("Failed to compute hash for {:?}: {}", path, e))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn unpack_archive(archive_path: &Path, target_dir: &Path) -> Result<(), String> {
    let path_str = archive_path.to_string_lossy();
    if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
        let file =
            File::open(archive_path).map_err(|e| format!("Failed to open archive: {}", e))?;
        let tar = GzDecoder::new(file);
        let mut archive = Archive::new(tar);
        archive
            .unpack(target_dir)
            .map_err(|e| format!("Failed to unpack .tar.gz: {}", e))?;
        Ok(())
    } else {
        let status = Command::new("tar")
            .arg("-xf")
            .arg(archive_path)
            .arg("-C")
            .arg(target_dir)
            .status()
            .map_err(|e| format!("Failed to execute tar command: {}", e))?;
        if !status.success() {
            return Err(format!(
                "tar command exited with non-zero status: {:?}",
                status.code()
            ));
        }
        Ok(())
    }
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

pub fn build_package(package_dir: &Path) -> Result<(), String> {
    // Phase 1: Parse the Package Manifest
    if !package_dir.exists() {
        return Err(format!(
            "Package directory {:?} does not exist",
            package_dir
        ));
    }
    let manifest_path = package_dir.join("package.manifest");
    if !manifest_path.exists() {
        return Err(format!("Manifest file not found at {:?}", manifest_path));
    }

    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest file {:?}: {}", manifest_path, e))?;
    let manifest: PackageManifest = toml::from_str(&manifest_content)
        .map_err(|e| format!("Failed to parse manifest: {}", e))?;

    println!(
        "Building package: {} v{}",
        manifest.package.name, manifest.package.version
    );

    // Phase 2: Setup the Sandbox Workspace
    let monorepo_root = find_monorepo_root()?;
    let build_cache_parent = std::env::var("STRAYLIGHT_CACHE_DIR")
        .or_else(|_| std::env::var("STRAYLIGHT_BUILD_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| monorepo_root.join("build").join("straylight"));
    let build_cache_dir = build_cache_parent.join(format!(
        "{}-{}",
        manifest.package.name, manifest.package.version
    ));

    if build_cache_dir.exists() {
        fs::remove_dir_all(&build_cache_dir).map_err(|e| {
            format!(
                "Failed to clean build cache directory {:?}: {}",
                build_cache_dir, e
            )
        })?;
    }

    let src_dir = build_cache_dir.join("src");
    let dest_dir = build_cache_dir.join("dest");

    fs::create_dir_all(&src_dir)
        .map_err(|e| format!("Failed to create src directory {:?}: {}", src_dir, e))?;
    fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create dest directory {:?}: {}", dest_dir, e))?;

    // Phase 3: Retrieve and Verify Upstream Sources
    let download_path = if let Some(ref file_name) = manifest.source.file {
        let local_path = package_dir.join(file_name);
        if !local_path.exists() {
            return Err(format!("Local source file not found at {:?}", local_path));
        }
        let dest_path = src_dir.join(file_name);
        println!(
            "Copying local source file from {:?} to {:?}",
            local_path, dest_path
        );
        fs::copy(&local_path, &dest_path)
            .map_err(|e| format!("Failed to copy local source: {}", e))?;
        Some(dest_path)
    } else if let Some(ref url_str) = manifest.source.url {
        let filename = url_str
            .split('/')
            .last()
            .filter(|s| !s.is_empty())
            .unwrap_or("source.archive");

        let dest_path = src_dir.join(filename);
        println!("Downloading {} from {} ...", filename, url_str);

        let response = ureq::get(url_str)
            .call()
            .map_err(|e| format!("Failed to download source from {}: {}", url_str, e))?;

        let mut reader = response.into_reader();
        let mut file = File::create(&dest_path)
            .map_err(|e| format!("Failed to create file {:?}: {}", dest_path, e))?;

        io::copy(&mut reader, &mut file)
            .map_err(|e| format!("Failed to write downloaded data: {}", e))?;
        Some(dest_path)
    } else if let Some(ref git_url) = manifest.source.git {
        println!("Cloning git repository from {} ...", git_url);
        let status = Command::new("git")
            .arg("clone")
            .arg(git_url)
            .arg(&src_dir)
            .status()
            .map_err(|e| format!("Failed to execute git clone: {}", e))?;
        if !status.success() {
            return Err(format!(
                "git clone exited with non-zero status: {:?}",
                status.code()
            ));
        }
        None
    } else {
        return Err("Source must specify one of 'url', 'file', or 'git'".to_string());
    };

    // Verify Checksum if applicable (non-git sources require checksum)
    if let Some(ref path) = download_path {
        if let Some(ref checksum) = manifest.source.checksum {
            match checksum.algorithm.as_str() {
                "sha256" => {
                    let computed_hash = compute_file_sha256(path)?;
                    if computed_hash != checksum.value {
                        let _ = fs::remove_file(path);
                        return Err(format!(
                            "Integrity check failed. Expected SHA256 ({}): {}, Got: {}",
                            checksum.algorithm, checksum.value, computed_hash
                        ));
                    }
                    println!("Integrity check passed (SHA256: {})", computed_hash);
                }
                other => {
                    return Err(format!("Unsupported checksum algorithm: {}", other));
                }
            }
        } else {
            return Err("Checksum configuration is required for file and url sources".to_string());
        }

        println!("Unpacking source archive {:?} inside {:?}", path, src_dir);
        unpack_archive(path, &src_dir)?;
    }

    // Phase 4: Stage Configuration and Scripts
    let justfile_src = package_dir.join("package.justfile");
    if !justfile_src.exists() {
        return Err(format!(
            "Required package.justfile not found at {:?}",
            justfile_src
        ));
    }
    let justfile_dest = build_cache_dir.join("package.justfile");
    fs::copy(&justfile_src, &justfile_dest)
        .map_err(|e| format!("Failed to stage package.justfile: {}", e))?;

    // Phase 5: Execute Sandbox Compilation (systemd-nspawn)
    if !is_root() {
        return Err("Unauthorized: 'straylight build' requires root/sudo privileges to run systemd-nspawn sandboxes.".to_string());
    }

    let compiler_root_env = std::env::var("STRAYLIGHT_COMPILER_ROOT")
        .or_else(|_| std::env::var("STRAYLIGHT_BUILD_ENV"));
    let compiler_root_buf = compiler_root_env
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/straylight/envs/@builder_active"));
    let compiler_root = compiler_root_buf.as_path();
    if !compiler_root.exists() {
        return Err(format!(
            "Sandbox base environment not found at {:?}",
            compiler_root
        ));
    }

    let mut cmd = Command::new("systemd-nspawn");

    let abs_workspace_path = build_cache_dir.canonicalize().map_err(|e| {
        format!(
            "Failed to canonicalize workspace path {:?}: {}",
            build_cache_dir, e
        )
    })?;

    cmd.arg("-D").arg(compiler_root)
        .arg("--bind").arg(format!("{}:/workspace", abs_workspace_path.to_string_lossy()))
        .arg("--as-pid2")
        .arg("/usr/bin/just").arg("-f").arg("/workspace/package.justfile").arg("-d").arg("/workspace/src").arg("build").arg("package").arg("/workspace/dest");

    if let Some(ref cflags) = manifest.build.cflags {
        if !cflags.is_empty() {
            cmd.env("CFLAGS", cflags.join(" "));
        }
    }

    if let Some(ref ldflags) = manifest.build.ldflags {
        if !ldflags.is_empty() {
            cmd.env("LDFLAGS", ldflags.join(" "));
        }
    }

    if let Some(ref env_map) = manifest.build.env {
        for (k, v) in env_map {
            cmd.env(k, v);
        }
    }

    println!("Spawning systemd-nspawn build...");
    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run systemd-nspawn command: {}", e))?;

    if !output.status.success() {
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        eprintln!("--- Sandbox build stdout ---");
        eprintln!("{}", stdout_str);
        eprintln!("--- Sandbox build stderr ---");
        eprintln!("{}", stderr_str);
        return Err(format!(
            "Sandbox build exited with non-zero status: {:?}",
            output.status.code()
        ));
    }

    // Phase 6: Stage and Bundle Output Package
    let staging_dir = build_cache_dir.join("staging");
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .map_err(|e| format!("Failed to clear existing staging dir: {}", e))?;
    }
    fs::create_dir_all(&staging_dir).map_err(|e| format!("Failed to create staging dir: {}", e))?;

    let dest_usr = dest_dir.join("usr");
    let staging_usr = staging_dir.join("usr");
    if dest_usr.exists() {
        fs::rename(&dest_usr, &staging_usr)
            .map_err(|e| format!("Failed to move dest/usr to staging/usr: {}", e))?;
    } else {
        return Err(format!(
            "Expected build output directory {:?} was not created by the build process",
            dest_usr
        ));
    }

    let meta_dir = staging_dir.join("meta");
    fs::create_dir_all(&meta_dir)
        .map_err(|e| format!("Failed to create staging meta dir: {}", e))?;

    let meta_manifest = meta_dir.join("package.manifest");
    fs::copy(&manifest_path, &meta_manifest)
        .map_err(|e| format!("Failed to copy manifest to staging: {}", e))?;

    let hooks_src = package_dir.join("hooks");
    if hooks_src.exists() {
        let hooks_dest = meta_dir.join("hooks");
        copy_dir_all(&hooks_src, &hooks_dest)?;
    }

    let mut files_entries = Vec::new();
    traverse_staging(&staging_dir, &staging_dir, &mut files_entries)?;

    let ledger = FilesLedger {
        files: files_entries,
    };
    let ledger_toml =
        toml::to_string(&ledger).map_err(|e| format!("Failed to serialize files ledger: {}", e))?;

    let ledger_path = meta_dir.join("files.toml");
    fs::write(&ledger_path, ledger_toml)
        .map_err(|e| format!("Failed to write files ledger: {}", e))?;

    let binaries_dir = monorepo_root.join("build").join("packages");
    fs::create_dir_all(&binaries_dir)
        .map_err(|e| format!("Failed to create output directory: {}", e))?;

    let archive_filename = format!(
        "{}-{}-1.tar.gz",
        manifest.package.name, manifest.package.version
    );
    let archive_path = binaries_dir.join(&archive_filename);
    println!("Archiving staging root to {:?}", archive_path);
    create_tar_gz(&staging_dir, &archive_path)?;

    Ok(())
}
