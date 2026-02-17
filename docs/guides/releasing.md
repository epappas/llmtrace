# Release Runbook

How to cut a new release of LLMTrace. A single `v*` tag triggers the full pipeline.

## Prerequisites

- Push access to `main`
- GitHub secrets configured:
  - `CARGO_REGISTRY_TOKEN` -- crates.io API token (account-wide)
  - `PYPI_TOKEN` -- PyPI API token (account-wide)
  - `GITHUB_TOKEN` -- automatic, used for GHCR and GitHub Releases

## Step-by-step

### 1. Bump the version

```bash
./scripts/release.sh 0.2.0
```

This updates:
- `Cargo.toml` workspace version
- `llmtrace-core`, `llmtrace-storage`, `llmtrace-security` dependency versions

The script runs `cargo check` to verify the workspace compiles.

### 2. Commit and tag

```bash
git add Cargo.toml Cargo.lock
git commit -m "release: v0.2.0"
git tag v0.2.0
git push && git push --tags
```

The tag push triggers `.github/workflows/release.yml`.

### 3. Monitor the pipeline

```bash
gh run list --limit 1
gh run view <run-id>
```

## What the pipeline does

The release pipeline runs 7 jobs on a `v*` tag push:

| Job | Depends on | What it does | Duration |
|-----|-----------|--------------|----------|
| **Validate Tag** | - | Extracts version from tag, verifies it matches `Cargo.toml`, generates changelog | ~6s |
| **Test Suite** | Validate | `cargo fmt --check`, `cargo clippy`, `cargo test --workspace` | ~7m |
| **Publish to crates.io** | Test | Publishes crates in dependency order (core -> storage, security -> sdk, llmtrace) | ~1.5m |
| **Python Wheels** | Test | Builds wheels for x86_64, aarch64, macOS universal2 via maturin | ~1.5m |
| **Publish to PyPI** | Wheels | Uploads all wheels to PyPI as `llmtracing` | ~15s |
| **Build Binaries** | Test | Compiles `llmtrace-proxy` for Linux amd64 and macOS arm64 | ~10m |
| **Docker Build & Push** | Validate, Test | Multi-arch Docker image (amd64 + arm64) with Trivy scan, pushed to GHCR | ~2.5h |
| **GitHub Release** | All above | Creates release with changelog, attaches binaries and wheels | ~1m |

Total time: ~2.5 hours (bottleneck is Docker arm64 QEMU emulation).

## Published artifacts

After a successful release, the following are published:

| Channel | Package | Install command |
|---------|---------|-----------------|
| Install script | - | `curl -sS https://raw.githubusercontent.com/epappas/llmtrace/main/scripts/install.sh \| bash` |
| crates.io | [`llmtrace`](https://crates.io/crates/llmtrace) | `cargo install llmtrace` |
| PyPI | [`llmtracing`](https://pypi.org/project/llmtracing/) | `pip install llmtracing` (imports as `import llmtrace`) |
| GHCR | `ghcr.io/epappas/llmtrace-proxy` | `docker pull ghcr.io/epappas/llmtrace-proxy:<version>` |
| GitHub Release | Binaries + wheels | Download from [Releases](https://github.com/epappas/llmtrace/releases) |

### Crates published to crates.io (in order)

1. `llmtrace-core`
2. `llmtrace-storage`
3. `llmtrace-security`
4. `llmtrace-sdk`
5. `llmtrace` (the proxy)

### Crates NOT published (publish = false)

- `llmtrace-python` (published via PyPI instead)
- `llmtrace-wasm`
- `llmtrace-benchmarks`

### GitHub Release assets

- `llmtrace-proxy-linux-amd64` -- static Linux binary
- `llmtrace-proxy-macos-arm64` -- macOS Apple Silicon binary
- `llmtracing-<version>-cp312-...-manylinux_2_17_x86_64.whl`
- `llmtracing-<version>-cp312-...-manylinux_2_17_aarch64.whl`
- `llmtracing-<version>-cp312-...-macosx_..._universal2.whl`

## Version management

All crate versions are centralized in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.3"

[workspace.dependencies]
llmtrace-core = { path = "crates/llmtrace-core", version = "0.1.3" }
llmtrace-storage = { path = "crates/llmtrace-storage", version = "0.1.3" }
llmtrace-security = { path = "crates/llmtrace-security", version = "0.1.3" }
```

The `version` field alongside `path` is required for crates.io -- path is stripped during publish, so crates.io needs the version to resolve dependencies.

The release script (`scripts/release.sh`) updates all four version strings in one command.

## Validation

The pipeline validates that the tag version matches `Cargo.toml` before proceeding. If they don't match, the pipeline fails immediately.

## Prerelease tags

Tags containing a hyphen (e.g., `v0.2.0-rc1`) are automatically marked as prerelease on GitHub.

## Changelog

`CHANGELOG.md` is auto-updated by the pipeline. The GitHub Release job commits the updated changelog back to `main` after creating the release.

## Troubleshooting

### "already exists" on crates.io

The publish function handles this gracefully -- if a crate version is already published, it skips and continues. This can happen if a previous run partially published before failing.

### PyPI upload fails

- Verify `PYPI_TOKEN` secret is set and is account-wide (not scoped to a specific project)
- The PyPI package name is `llmtracing` (not `llmtrace` -- that name is taken)

### Docker build times out

The arm64 QEMU build takes ~2.5 hours. If it times out (GitHub's 6-hour limit), consider using native arm64 runners.

### Tag version mismatch

If you forget to bump before tagging:

```bash
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
./scripts/release.sh 0.2.0
git add Cargo.toml Cargo.lock
git commit -m "release: v0.2.0"
git tag v0.2.0
git push && git push --tags
```
