# TODO

## Done

- [x] Workspace scaffold: core, backends-age, backends-7z, cli, integration-tests
- [x] `Backend` trait shared interface (pack/verify/extract)
- [x] `age` backend: ChaCha20-Poly1305 + zstd, streaming progress
- [x] `7z` backend: shells out to system 7z/7zz/7za for compatibility
- [x] CLI with clap, indicatif progress bar, confirmed password prompts
- [x] Mandatory integrity verification before source deletion
- [x] Bilingual README (Persian/English), polished with badges/TOC/reference
- [x] CHANGELOG.md (Keep a Changelog style)
- [x] Project renamed to "ramz" (binary), checked for name collisions
- [x] Dual `MIT OR Apache-2.0` license
- [x] Unit + integration tests across every crate (integration tests now
      correctly discovered via a dedicated `integration-tests` crate)
- [x] `--argon2id` and `--mlkem` wired into the encryption path
- [x] `--resume` fully wired with checksum + completion verification
- [x] Configurable Argon2 parameters, stored in the archive header
- [x] `zeroize`/`Zeroizing` for all sensitive key material in memory
- [x] `IncompatibleFlag` error for `--backend seven-z` + `--argon2id`/`--mlkem`
- [x] `--secure-delete`: multi-pass overwrite before removal, for both
      single files and recursively for directories
- [x] `docs/ARCHIVE_FORMAT.md`: full byte-level spec of the `RMZ1` container
- [x] **Recipient-based ML-KEM encryption** (`ramz keygen`, `--recipient`,
      `--identity`) — a genuine post-quantum guarantee independent of any
      password, documented in `docs/IDENTITY_FORMAT.md`
- [x] GitHub Actions CI (test + clippy + fmt, with 7z installed)
- [x] GitHub Actions Release workflow (7 cross-compiled targets, real
      GitHub Release with changelog-derived notes)
- [x] GitHub issue and pull request templates (bilingual)

## Not done yet

- [ ] Independent security review of the `RMZ1` and `RIM1` formats
- [ ] Multi-recipient support (`--recipient key1 --recipient key2`)
- [ ] Streaming/chunked encryption for very large files (currently
      buffers the whole compressed payload in memory/temp file)
- [ ] Publish to crates.io / AUR
- [ ] Confirm the CI and Release workflows actually pass on GitHub's
      runners (reviewed and corrected locally, not yet verified live)
