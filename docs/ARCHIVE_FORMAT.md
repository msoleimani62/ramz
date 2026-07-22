# RMZ1 Archive Format Specification

## Overview

RMZ1 is the custom binary container format used by `ramz` when Argon2id
and/or ML-KEM post-quantum hybrid encryption is enabled with the age backend.
When neither flag is set, the standard age passphrase format is used instead.

> **Version:** 1.0
> **Magic:** `RMZ1` (0x52 0x4D 0x5A 0x31)

---

## Byte-Level Layout

All multi-byte integers are **little-endian**.

```
Offset    Size    Field
─────────────────────────────────────────────────────────────
0         4       Magic: "RMZ1"
4         1       Flags (bitfield)
5         4       Argon2 memory (KiB)
9         4       Argon2 iterations
13        4       Argon2 parallelism
17        16      Salt
33        *       ML-KEM fields (only if FLAG_MLKEM)
*         12      Payload nonce (ChaCha20-Poly1305)
*         *       Ciphertext (ChaCha20-Poly1305)
```

---

## Flags Byte

| Bit | Name          | Meaning                               |
|-----|---------------|---------------------------------------|
| 0   | FLAG_ARGON2ID | Always set (0x01). Uses Argon2id KDF. |
| 1   | FLAG_MLKEM    | ML-KEM-768 hybrid encryption (0x02).  |

```
flags = FLAG_ARGON2ID | (FLAG_MLKEM if mlkem enabled)
```

---

## ML-KEM Fields (present only when FLAG_MLKEM is set)

```
Offset    Size    Field
─────────────────────────────────────────────────────────────
33        4       Ciphertext length (u32 LE)
37        1088    ML-KEM-768 ciphertext
1125      12      DK nonce (ChaCha20-Poly1305)
1137      4       Encrypted DK length (u32 LE)
1141      *       Encrypted decapsulation key
```

The decapsulation key (DK) is encrypted with ChaCha20-Poly1305 using the
Argon2id-derived key. The shared secret is recovered via ML-KEM decapsulation
and combined with the Argon2id key via SHA-256 to produce the final 256-bit
payload encryption key.

---

## Key Derivation Flow

### Encryption (pack)

```
salt = random(16)
argon2_key = Argon2id(password, salt, memory, iterations, parallelism)

if ML-KEM:
    (ek, dk) = ML-KEM-768.generate_keypair()
    (ct, ss) = ek.encapsulate()
    dk_encrypted = ChaCha20-Poly1305(argon2_key, nonce_dk, dk)
    final_key = SHA-256(argon2_key || ss)
else:
    final_key = argon2_key

payload = ChaCha20-Poly1305(final_key, nonce_payload, zstd(tar))
```

### Decryption (extract/verify)

```
argon2_key = Argon2id(password, salt, memory, iterations, parallelism)

if ML-KEM:
    dk = ChaCha20-Poly1305_decrypt(argon2_key, nonce_dk, dk_encrypted)
    ss = ML-KEM-768.decapsulate(dk, ct)
    final_key = SHA-256(argon2_key || ss)
else:
    final_key = argon2_key

tar = zstd_decompress(ChaCha20-Poly1305_decrypt(final_key, nonce_payload, ciphertext))
```

---

## Security Properties

| Threat Model             | Protection                                      |
|--------------------------|-------------------------------------------------|
| Brute-force password     | Argon2id memory-hard KDF                        |
| Quantum computer (Grover)| ML-KEM-768 post-quantum key encapsulation       |
| Key material in memory   | Zeroizing wrappers on all sensitive material    |
| Tampering                | ChaCha20-Poly1305 AEAD authentication           |

---

## Backward Compatibility

Argon2 parameters (`memory_kib`, `iterations`, `parallelism`) are stored in
the header. Archives created with different parameters remain decryptable
because the decryptor reads these values from the header rather than using
hardcoded defaults.

---

## Future Versions

- **v1.1 (planned):** Recipient-based identity files (no password).
- **v1.2 (planned):** Chunked streaming with per-chunk authentication.
