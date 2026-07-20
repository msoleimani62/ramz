# TODO

## Done

- [x] Workspace scaffold: core, backends-age, backends-7z, cli
- [x] `Backend` trait shared interface
- [x] `age` engine: X25519 + ChaCha20-Poly1305 + zstd, streaming progress
- [x] `7z` engine: shells out to system 7z/7zz/7za for compatibility
- [x] CLI with clap, indicatif progress bar, confirmed password prompts
- [x] Mandatory integrity verification before source deletion
- [x] Bilingual README (Persian/English)
- [x] CHANGELOG.md (Keep a Changelog + SemVer)
- [x] Project renamed to "ramz", checked for name collisions
- [x] First successful `cargo build --release` on Kali NetHunter chroot
- [x] Fixed: triple-slash doc comments leaking Persian text into `--help` output
- [x] Explicit English-only `help =` text on every CLI argument
- [x] LICENSE file (MIT) added
- [x] Unit tests across core, backends-age, backends-7z
- [x] Bug fix: safe_output_dir() for root-level source paths
- [x] Bug fix: configurable compression level (was hardcoded in age backend)
- [x] Replaced hand-rolled temp dir with the tempfile crate
- [x] 7z backend now surfaces real stderr output on failure

## Not done yet

- [ ] GitHub repository created and initial commit pushed
- [ ] Confirm .github/workflows CI/release files (excluded from last zip by mistake)
- [ ] Unit tests (core packing/unpacking, error paths)
- [ ] Integration tests (full pack + verify round-trip for both engines)
- [ ] Property-based tests (proptest) for edge cases
- [ ] Argon2id key derivation (currently age's default scrypt-based KDF)
- [ ] Post-quantum hybrid encryption option (ML-KEM)
- [ ] File-type-aware compression (skip already-compressed files like jpg/mp4)
- [ ] Resume support for interrupted large archives
- [ ] Dry-run mode (preview output size before running)
- [ ] CI pipeline (build + test on push)
- [ ] Cross-compiled release binaries (Termux/aarch64-android, Linux distros)
- [ ] Automated version bump / release process
