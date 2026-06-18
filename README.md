# Straylight - Freeside OS Package Engine & CLI

`straylight` is the core package manager and system synchronization daemon for Freeside OS. Written in Rust, it manages declarative packages, coordinates isolated builds, and syncs host system states transactionally.

## Architecture

Straylight is split into two distinct execution domains:

1.  **Lightweight User-Space CLI (`straylight`)**:
    An unprivileged command-line front-end used by operators to trigger builds, configure packages, and initiate system syncs.
2.  **Privileged Back-End Daemon (`straylightd`)**:
    An on-demand system daemon activated via a systemd socket (`/run/straylightd.sock`). It performs privileged filesystem mutations (such as overlayfs resets, Btrfs subvolume swaps, and system updates).

## Key Features

*   **Isolated Sandboxed Compilation**: Builds packages inside disposable `systemd-nspawn` compiler containers.
*   **Declarative Synchronization**: Reconciles the active operating system boot layers with your desired state configured in `/etc/freeside/packages.toml`.
*   **State Reset & Diffing**: Provides instant reset-to-default capabilities via OverlayFS configuration cleanup, as well as diff tools for tracked packages.
*   **Transactional Updates**: Leverages Btrfs subvolumes and casync chunks for zero-downtime, atomized package deployment.

## CLI Command Usage

### 1. Build and Package
Compile a package target locally:
```bash
straylight build ./packages/<package-name>
```

Pack compiled outputs into a compressed tarball:
```bash
straylight package ./packages/<package-name> --out ./artifacts/<package-name>.tar.gz
```

### 2. Distribute and Release
Populate chunk indices and distribute the package:
```bash
straylight distribute ./artifacts/<package-name>.tar.gz
```

Combine build, package, and index publication into a single action:
```bash
straylight release ./packages/<package-name>
```

### 3. Maintain and Synchronize
Synchronize the running system configuration with `/etc/freeside/packages.toml`:
```bash
straylight sync
```

Diff or reset package configurations to factory defaults:
```bash
straylight diff <package-name>
straylight reset <package-name>
```

## Compilation

Build the Rust codebase using Cargo:
```bash
cargo build --release
```
The compiled binary will be located at `target/release/straylight`.
