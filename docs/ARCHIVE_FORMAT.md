# RMZ1 Archive Format Specification

## Overview

RMZ1 is the custom binary container format used by `ramz` when `--argon2id`, `--mlkem`, or `--recipient` flags are enabled. It provides authenticated encryption with ChaCha20-Poly1305 over zstd-compressed tar archives.

## Magic Bytes

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0      | 4    | `RMZ1` | Format identifier |

## Header Layout (v1.1)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0      | 4    | bytes | Magic: `RMZ1` |
| 4      | 1    | u8    | Flags bitfield |
| 5      | 4    | u32 LE | Argon2 memory (KiB) |
| 9      | 4    | u32 LE | Argon2 iterations |
| 13     | 4    | u32 LE | Argon2 parallelism |
| 17     | 16   | bytes | Argon2 salt |

### Flags Bitfield

| Bit | Flag | Description |
|-----|------|-------------|
| 0   | `FLAG_ARGON2ID` (0x01) | Argon2id KDF enabled |
| 1   | `FLAG_MLKEM` (0x02) | ML-KEM hybrid encryption |
| 2   | `FLAG_RECIPIENT` (0x04) | Recipient-based encryption |

## Mode-Specific Fields

### Argon2id-only mode (flags = 0x01)

No additional fields after salt. `final_key = argon2_key`.

### ML-KEM hybrid mode (flags = 0x03)

| Field | Size | Description |
|-------|------|-------------|
| `mlkem_ct_len` | 4 | u32 LE |
| `mlkem_ct` | `mlkem_ct_len` | ML-KEM ciphertext |
| `dk_nonce` | 12 | ChaCha20-Poly1305 nonce |
| `dk_enc_len` | 4 | u32 LE |
| `dk_encrypted` | `dk_enc_len` | Encrypted decapsulation key |

`final_key = SHA-256(argon2_key || mlkem_shared_secret)`

### Recipient mode (flags = 0x05)

| Field | Size | Description |
|-------|------|-------------|
| `mlkem_ct_len` | 4 | u32 LE |
| `mlkem_ct` | `mlkem_ct_len` | ML-KEM ciphertext (encapsulated to recipient) |

`final_key = mlkem_shared_secret` (no Argon2 involved)

**Important:** No decapsulation key is stored in the archive. Only the recipient's identity file can decrypt.

**Note on the flags byte:** `FLAG_ARGON2ID` is always set by the current
implementation, even in pure recipient mode where the Argon2 salt/
parameters in the header are written but never actually used to derive
`final_key`. A format implementer should treat `FLAG_RECIPIENT` as
taking priority over `FLAG_ARGON2ID` when both are set — the recipient
path in the reference implementation checks `FLAG_RECIPIENT` first and
never touches the Argon2 fields for key derivation in that case.

## Payload

After mode-specific fields:

| Field | Size | Description |
|-------|------|-------------|
| `payload_nonce` | 12 | ChaCha20-Poly1305 nonce |
| `ciphertext` | variable | Encrypted zstd-compressed tar |

## Decryption Flow

1. Read magic and verify `RMZ1`
2. Read flags, Argon2 params, salt
3. If `FLAG_RECIPIENT`: decapsulate with identity's `dk`
4. If `FLAG_MLKEM`: derive Argon2 key, decrypt `dk`, decapsulate
5. If Argon2id-only: derive Argon2 key
6. Decrypt payload with `final_key`
7. Decompress zstd
8. Extract tar

## Security Properties

- **Confidentiality:** ChaCha20-Poly1305 with 256-bit key
- **Integrity:** Poly1305 authentication tag (16 bytes appended by AEAD)
- **Post-quantum (recipient mode):** ML-KEM-768; no password to crack
- **Post-quantum (hybrid mode):** Argon2id + ML-KEM; password required but quantum-resistant
