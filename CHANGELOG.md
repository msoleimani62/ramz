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

## [0.2.0] - 2026-07-20

### Added
- `--argon2id` flag added to the CLI (scaffolded)
- `--mlkem` flag added to the CLI (scaffolded)
- File-type-aware compression (skips already-compressed files: jpg/mp4/pdf/etc.)
- `--dry-run` mode for previewing archive size and settings
- `--resume` flag added to the CLI
- Property-based tests (proptest) and integration tests

### Known limitations
- `--argon2id` and `--mlkem` were added to the CLI in this version but were
  not actually connected to the encryption path yet — see [0.2.1] Fixed.
- `--resume` only suppressed the "archive exists" check; it did not resume
  interrupted archives.
- CI/release GitHub Actions workflows present but not yet confirmed working.

## [0.2.1] - 2026-07-21

### Fixed
- Updated `ml-kem` dependency usage to match the 0.3.2 API (upstream
  breaking change: `Kem::generate_keypair()`/`encapsulate()` replace the
  old `_from_rng` variants; requires the `getrandom` feature).
- Fixed an invalid Argon2 test salt (was below the 8-byte minimum).
- Fixed a `ramz-backend-7z` crate name mismatch that broke the build.
- Fixed `SevenZBackend` usage (it is a unit struct with no `new()`).
- Implemented the missing `SevenZBackend::extract` method.
- Fixed the `age` backend's `extract` path, which was missing a zstd
  decompression step and silently produced corrupted output.
- **`--argon2id` and `--mlkem` are now actually wired into the encryption
  path.** Previously these flags were accepted but silently ignored — the
  archive was always encrypted with age's plain default KDF regardless of
  the flags. See Security below and the README's "Security design"
  section for exactly what each flag does now.
- **`--resume` is now actually wired.** Checks the source checksum,
  verifies archive state, and either skips a completed archive or reports
  a clear mismatch error — instead of only suppressing the "archive
  exists" check.
- New `IncompatibleFlag` error variant: `--argon2id`/`--mlkem` combined
  with `--backend seven-z` now produce a clear error instead of a silent
  no-op.
- Fixed cross-compilation failures for the `x86_64-unknown-linux-musl`
  and `aarch64-linux-android` release targets (`zstd-sys` couldn't find
  a suitable C cross-compiler; CI now installs `musl-tools` and points
  `cc-rs` at the Android NDK's clang).
- Removed unused-import compiler warnings across `cli` and `core`.

### Added
- `--secure-delete` flag: overwrites file content before removing the
  source (best-effort — not a guarantee on SSDs with wear-leveling; this
  limitation is documented, not glossed over).
- `docs/ARCHIVE_FORMAT.md`: full byte-level specification of the `RMZ1`
  custom container format.
- `--argon2-memory-kib`, `--argon2-iterations`, `--argon2-parallelism`
  flags for configurable Argon2 parameters (backward-compatible
  defaults). Parameters are stored in the `RMZ1` container header so
  archives remain decryptable even if defaults change later.

### Security
- `--argon2id`: password-based key derivation now genuinely uses
  memory-hard Argon2id (64 MiB, 3 iterations, parallelism 4 by default)
  instead of silently falling back to age's default scrypt-based KDF.
- `--mlkem`: introduces a custom archive container (`RMZ1` magic bytes)
  that combines the Argon2id-derived key with a per-archive ML-KEM-768
  shared secret via SHA-256, as hybrid hardening. This is defense-in-depth,
  not a substitute for password strength — see the README for the exact
  threat model.
- The final encryption key is now wrapped in `Zeroizing<[u8; 32]>`, and
  `MlKemKeyPair` implements manual `Zeroize`/`ZeroizeOnDrop`, clearing
  sensitive key material from memory when it goes out of scope
  (defense-in-depth against cold-boot and memory-dump attacks).
- Added 11 new tests covering wrong-password rejection, backend/flag
  incompatibility, and full pack→verify→extract round-trips for
  `--argon2id`, `--mlkem`, and `--secure-delete`.

### Known limitations
- `--argon2id`/`--mlkem` apply only to the `age` backend.
- No independent security review has been performed on the `RMZ1`
  container format.
- ML-KEM hybrid hardening (`--mlkem`) does not protect against password
  compromise — see the README's "Security design" section for the exact
  threat model. A true recipient-key post-quantum workflow is planned
  (tracked in ROADMAP.md).
