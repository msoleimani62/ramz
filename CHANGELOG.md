# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - 2026-08-17

### Fixed
- **`compute_file_checksum()` for directory sources was not recursive**: it only listed the top level with `fs::read_dir`, silently ignoring every file inside subdirectories. As a result, `--resume` and `verify_source_unchanged()` could report a directory source as "unchanged" even though a nested file had been added, removed, or modified — the exact same class of bug the 0.2.2 resume fix addressed, but for a case that bug's tests never covered. Now walks the full tree recursively with `walkdir` and hashes each file's relative path (so renames are also detected) alongside its content. Added a regression test (`test_compute_file_checksum_detects_nested_change`).
- **Malformed/truncated identity and archive-header files could crash the program (`panic`) instead of returning a clean error**: `Identity::load_with_password()`, the `--recipient` public-key parser in the CLI, and `decrypt_custom_container()`'s `RMZ1` header parser all indexed raw byte slices directly (`raw[a..b]`) with no bounds checking. A corrupted, truncated, or adversarially crafted identity/archive/recipient file would trigger an out-of-bounds index panic — a real crash, not a `Result::Err` — anywhere these files are handled. All three now use bounds-checked (`.get()`/`checked_add`) parsing and return `RamzError::Backend` on malformed input. Added regression tests: `test_corrupted_custom_container_header_does_not_panic`, `test_load_truncated_identity_does_not_panic`, `test_load_truncated_public_identity_does_not_panic`, `test_pack_with_corrupted_recipient_file_does_not_panic`.

### Security
- Documented (in-code, `backends-7z/src/lib.rs`) a known, previously-unstated limitation: the `7z` backend passes the password to the external `7z`/`7zz`/`7za` binary as a command-line argument, which is briefly visible to other local users on the same machine via `ps aux` or `/proc/<pid>/cmdline` while the process runs. This is a limitation of the external 7z binary itself (it has no stdin/env password input) and cannot be eliminated while shelling out to it — only documented. No code behavior changed.

## [0.3.0] - 2026-07-24

### Added
- **Recipient-based encryption (`ramz keygen`, `--recipient`)**: True post-quantum encryption where only the holder of the identity secret key can decrypt. No password involved in the encryption path.
- `ramz keygen` subcommand: Generate ML-KEM-768 identity keypairs
- `--recipient <path>` flag for `ramz pack`: Encrypt for a specific recipient
- `--identity <path>` flag for `ramz verify` and `ramz extract`: Decrypt recipient-based archives
- `docs/IDENTITY_FORMAT.md`: Specification for RIM1 identity format
- `verify_with_identity()` and `extract_to_dir()` methods on `AgeBackend`
- Integration tests for recipient roundtrip, password-protected identities, and error cases
- `Backend::extract()` trait method for unified extraction interface
- Dual `MIT OR Apache-2.0` licensing (adds a patent grant on top of MIT; standard for the Rust ecosystem)
- GitHub issue and pull request templates (bilingual)

### Changed
- `Backend` trait now includes `extract()` method
- `AgeBackend::verify()` delegates to `decrypt_archive_to_tar()` with `None` identity
- Archive format bumped to v1.1 with `FLAG_RECIPIENT` support
- `SevenZBackend` updated to implement `extract()` trait method
- CLI package renamed from `ramz` to `ramz-cli` for consistency with the other workspace crates (`ramz-core`, `ramz-backends-age`, `ramz-backend-7z`); the binary itself is still named `ramz`, so `ramz pack ...` is unaffected
- Identity secret-key files without a password now store the decapsulation key directly (with `chmod 600`) instead of "encrypting" it with a random key stored in the same file — the old approach provided zero protection beyond plaintext while adding complexity and the illusion of security
- `--secure-delete` on a directory source now recursively overwrites every file inside it, not just the top-level entry
- Integration tests moved into a dedicated `integration-tests` workspace member so `cargo test --workspace` actually discovers and runs them (they previously lived at the repo root, outside any crate, and were silently never executed)

### Fixed
- `SevenZBackend` no longer uses non-existent `new()` constructor
- CLI `Verify` subcommand now supports `--identity` for recipient archives
- CLI `Extract` subcommand properly routes to `AgeBackend::extract_to_dir()` for recipient archives
- `ml-kem` workspace dependency was pinned to the incompatible `0.2` line (missing the `getrandom` feature); restored to `0.3` with `getrandom`
- `argon2` workspace dependency was missing the `password-hash` feature required by `argon2::password_hash::SaltString`/`PasswordHasher`
- CLI leaked identity password memory via `String::leak()` in `Verify` and `Extract` (contradicting the zeroization work elsewhere in the codebase); now kept in a normally-scoped variable
- The `--resume` completion check regressed to only comparing the source checksum, without confirming `processed_bytes == total_bytes` or that the archive file exists — reintroducing the false-completion bug fixed in 0.2.2; restored the full three-way check (mismatch / complete / incomplete-so-redo)
- `release.yml` had been simplified to only upload build artifacts, without creating an actual GitHub Release or extracting notes from `CHANGELOG.md`; restored release creation, and re-added the `musl-tools` and Android NDK compiler configuration needed for the `x86_64-unknown-linux-musl` and `aarch64-linux-android` cross-builds
- `ci.yml` didn't install a `7z` binary, so any test exercising the 7z backend would fail on CI
- `mlkem_hybrid.rs` had reverted to referencing a nonexistent `ml-kem` API (`KemCore`, `Encoded`, `EncodedSizeUser`, `MlKem768Params`, `.generate()`) that doesn't exist in any published version of the crate; restored to the verified 0.3.2 API (`Kem::generate_keypair()`, `Encapsulate::encapsulate()`, `Decapsulate::decapsulate()`)
- `ramz verify --identity` always prompted for a generic password first, even for identity-based archives, before separately prompting for the identity password — a confusing double-prompt; now only prompts for the identity password when `--identity` is used
- `ramz extract` without `-p`/`--identity` passed `None` straight to the backend instead of prompting interactively like `pack` and `verify` do, so it just errored out instead of giving the user a chance to type a password
- `Cargo.lock` was listed in `.gitignore`; for a binary/application project (not a library), it should be committed for reproducible builds
- A stray, outdated single-license `LICENSE` file was left behind alongside the new `LICENSE-MIT`/`LICENSE-APACHE` split from a prior merge; removed
- `docs/IDENTITY_FORMAT.md` still described the old (removed) "storage key embedded in file" no-password layout; updated to match the current format (protection-flag byte, direct key storage)
- Restored real end-to-end pack/verify/extract integration tests for the `7z` backend, which had been reduced to a single metadata-only test during a rewrite, leaving the entire 7z encryption path without coverage

### Security
- Recipient-based encryption (`--recipient`) is a genuinely different security model from `--mlkem`: the decapsulation key never enters the archive, so possessing the archive plus a correct guess of any password provides no path to the plaintext — only physical possession of the recipient's identity file does. See the README's "Security design" section for the full threat-model comparison with `--mlkem`.
- Identity secret-key files are protected by filesystem permissions (`chmod 600`) at minimum, and additionally by Argon2id + ChaCha20-Poly1305 encryption when a password is supplied at `ramz keygen` time.

### Known limitations
- No independent security review has been performed on the `RMZ1` archive format or the `RIM1` identity format.
- Recipient archives currently support exactly one recipient; multi-recipient support (like `age -r key1 -r key2`) is not implemented.
- The encryption pipeline is not streaming — very large files are held in memory/temp files during pack, which may be slow or memory-intensive on constrained devices.
- Secure delete is best-effort and provides no guarantee on SSDs/flash storage with wear-leveling; see the in-code documentation on `secure_delete_file()`.

## [0.2.1] - 2026-07-20

### Added
- `--argon2id` flag: Argon2id-based key derivation with tunable parameters
- `--mlkem` flag: Post-quantum ML-KEM-768 hybrid encryption
- `--resume` flag: Resume interrupted archive creation
- `--dry-run` flag: Preview archive without creating it
- `--secure-delete` flag: Overwrite source before deletion
- `docs/ARCHIVE_FORMAT.md`: Specification for RMZ1 archive format
- `CHANGELOG.md`: Project changelog
- CI workflow for automated testing
- Release workflow with cross-compilation for 7 targets

### Fixed
- Resume falsely reported completed archives that were never created
- README accidentally committed with stale content

## [0.2.0] - 2026-07-18

### Added
- `age` backend with passphrase encryption
- `7z` backend with external binary integration
- `ramz_core` crate with shared types and utilities
- Progress reporting with indicatif
- Password confirmation and validation

## [0.1.0] - 2026-07-15

### Added
- Initial project scaffold
- Basic tar + zstd + age encryption pipeline
