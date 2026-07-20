# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial workspace scaffold: `core`, `backends-age`, `backends-7z`, `cli`.
- `Backend` trait as the shared interface for all compression/encryption engines.
- `age` engine (default): X25519 + ChaCha20-Poly1305 via the `age` crate, zstd
  compression, streaming progress reporting.
- `7z` engine (compatibility mode): shells out to a system `7z`/`7zz`/`7za`
  binary for interoperability with other tools.
- CLI (`ramz`) with `clap`-based argument parsing, `indicatif` progress bar,
  confirmed password prompts via `rpassword`.
- Mandatory post-write integrity verification before source deletion.
- Bilingual (Persian/English) README.
- MIT `LICENSE` file.
- `safe_output_dir()` helper to prevent invalid output paths on root-level sources.
- `read_and_confirm_password()` centralized in `core`, removing duplicate logic from the CLI.
- Unit tests across `core`, `backends-age`, and `backends-7z`.
- `rustfmt.toml` for consistent code style.
- Local pre-commit hooks for fmt, clippy, and test.

### Changed
- `backends-age` now uses the `tempfile` crate instead of a hand-rolled temp
  directory implementation.
- `backends-age` compression level is now configurable via `--compression`
  instead of a hardcoded value.
- `backends-7z` now clamps the compression level to the valid 0-9 range and
  surfaces the underlying `7z` process's stderr output on failure.
- Archive extension for the `age` engine renamed from `sa-age` to `ramz-age`
  to match the project's final name.

### Known limitations
- CI/release GitHub Actions workflows are being set up but not yet confirmed
  present in this snapshot.
- Only two engines implemented so far; Argon2id key derivation and
  post-quantum hybrid encryption are planned but not started.
