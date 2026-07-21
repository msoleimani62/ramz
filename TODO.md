# TODO

## Done

- [x] Workspace scaffold: core, backends-age, backends-7z, cli
- [x] `Backend` trait shared interface
- [x] `age` engine: X25519 + ChaCha20-Poly1305 + zstd, streaming progress
- [x] `7z` engine: shells out to system 7z/7zz/7za for compatibility
- [x] CLI with clap, indicatif progress bar, confirmed password prompts
- [x] Mandatory integrity verification before source deletion
- [x] Bilingual README (Persian/English), polished with badges/TOC/reference
- [x] CHANGELOG.md (Keep a Changelog + SemVer)
- [x] Project renamed to "ramz", checked for name collisions
- [x] First successful `cargo build --release` on Kali NetHunter chroot
- [x] Fixed: triple-slash doc comments leaking Persian text into `--help` output
- [x] Explicit English-only `help =` text on every CLI argument
- [x] LICENSE file (MIT) added
- [x] Unit tests across core, backends-age, backends-7z (19 tests)
- [x] Bug fix: safe_output_dir() for root-level source paths
- [x] Bug fix: configurable compression level (was hardcoded in age backend)
- [x] Replaced hand-rolled temp dir with the tempfile crate
- [x] 7z backend now surfaces real stderr output on failure
- [x] Confirmed: `cargo test --workspace` → all tests passing
- [x] GitHub repository created and initial commit pushed
- [x] `--argon2id` and `--mlkem` wired into encryption path (v0.2.1)
- [x] `--resume` fully wired with checksum verification (v0.2.2)
- [x] Configurable Argon2 params with header storage (v0.2.2)
- [x] `zeroize` for all sensitive key material (v0.2.2)
- [x] `IncompatibleFlag` error for 7z + argon2id/mlkem (v0.2.2)

## Not done yet

- [ ] Confirm `.github/workflows` CI/release files (excluded from last zip by mistake)
- [ ] Property-based tests (proptest) for edge cases — partially done, needs expansion
- [ ] CI pipeline (build + test on push) — verify on GitHub Actions
- [ ] Cross-compiled release binaries (Termux/aarch64-android, Linux distros)
- [ ] Automated version bump / release process
- [ ] Independent security audit of `RMZ1` container format
- [ ] Recipient-based identity (ML-KEM public key files, `ramz keygen`)
- [ ] Streaming resume (currently resume only skips completed archives)
