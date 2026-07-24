# RIM1 Identity Format Specification

## Overview

RIM1 (Ramz Identity Mark 1) is the key format for ML-KEM-768 identities used with `--recipient` encryption. Each identity consists of a public key file (`identity.pub`) and a secret key file (`identity`).

## Public Key File (`identity.pub`)

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0      | 7    | `RIM1PUB` | Magic bytes |
| 7      | 4    | u32 LE | Encapsulation key length |
| 11     | 1184 | bytes | ML-KEM-768 encapsulation key |

## Secret Key File (`identity`)

The second byte of the file (right after the magic) is a **protection
flag** that tells the loader which layout follows:

| Flag value | Meaning |
|---|---|
| `0x00` (`PROTECTION_NONE`) | No password — the decapsulation key is stored directly |
| `0x01` (`PROTECTION_PASSWORD`) | Password-protected — the decapsulation key is encrypted |

### Without Password Protection (flag = `0x00`)

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0      | 7    | `RIM1SEC` | Magic bytes |
| 7      | 1    | `0x00` | Protection flag |
| 8      | 4    | u32 LE | Decapsulation key length |
| 12     | 2400 | bytes | Decapsulation key, stored **unencrypted** |

There is no encryption layer in this mode. Earlier revisions of this
format "encrypted" the key with a random key stored right next to it in
the same file — that provided zero protection beyond plaintext while
adding complexity and the illusion of security, so it was removed. In
this mode, the only real protection is the filesystem permission
(`chmod 600`, see below) — the same approach `ssh-keygen` takes for a
passphrase-less key.

### With Password Protection (flag = `0x01`)

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0      | 7    | `RIM1SEC` | Magic bytes |
| 7      | 1    | `0x01` | Protection flag |
| 8      | 16   | bytes | Argon2id salt |
| 24     | 12   | bytes | ChaCha20-Poly1305 nonce |
| 36     | 4    | u32 LE | Ciphertext length |
| 40     | 2400 | bytes | Decapsulation key, encrypted with ChaCha20-Poly1305 under the Argon2id-derived key |

The Argon2 key is derived with: memory=65536 KiB, iterations=3, parallelism=4.
In this mode, the decryption key is never stored in the file at all — it
exists only as a function of the password, so this is real encryption,
not just obfuscation.

## File Permissions

On Unix systems, the secret key file is created with mode `0o600` (owner read/write only).

## Security Considerations

- The public key file (`identity.pub`) can be shared freely.
- The secret key file (`identity`) must never be shared.
- Password protection provides real cryptographic confidentiality if the
  secret key file is stolen (the key is genuinely derived from the
  password, not embedded in the file).
- Without password protection, the only protection is the filesystem
  permission bit (`chmod 600`) — there is no cryptographic layer to
  defeat, by design, since one that used a key stored alongside the
  data would provide no real security anyway.
- ML-KEM-768 is NIST FIPS 203 compliant and post-quantum secure.

## Key Sizes

| Component | Size |
|-----------|------|
| Encapsulation key (ek) | 1184 bytes |
| Decapsulation key (dk) | 2400 bytes |
| Ciphertext (ct) | 1088 bytes |
| Shared secret (ss) | 32 bytes |
