use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::SecretString;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ramz_core::{Backend, PackOptions, ProgressReporter, RamzError, Result, SourceKind, Target};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub mod argon2_kdf;
pub mod identity;
pub mod mlkem_hybrid;

// Binary magic bytes identifying the custom archive container
// بایت‌های جادویی شناسایی کانتینر آرشیو سفارشی
const RAMZ_MAGIC: &[u8; 4] = b"RMZ1";
const FLAG_ARGON2ID: u8 = 0b01;
const FLAG_MLKEM: u8 = 0b10;
const FLAG_RECIPIENT: u8 = 0b100;

pub struct AgeBackend {
    use_argon2id: bool,
    use_mlkem: bool,
    use_recipient: bool,
    recipient_key: Option<Vec<u8>>,
}

impl Default for AgeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl AgeBackend {
    pub fn new() -> Self {
        Self {
            use_argon2id: false,
            use_mlkem: false,
            use_recipient: false,
            recipient_key: None,
        }
    }

    pub fn new_with_argon2id() -> Self {
        Self {
            use_argon2id: true,
            use_mlkem: false,
            use_recipient: false,
            recipient_key: None,
        }
    }

    pub fn new_with_mlkem() -> Self {
        Self {
            use_argon2id: false,
            use_mlkem: true,
            use_recipient: false,
            recipient_key: None,
        }
    }

    pub fn new_with_recipient(recipient_pub_key: Vec<u8>) -> Self {
        Self {
            use_argon2id: false,
            use_mlkem: false,
            use_recipient: true,
            recipient_key: Some(recipient_pub_key),
        }
    }

    // Decrypt standard age format to writer
    // رمزگشایی فرمت استاندارد age به writer
    pub fn decrypt_to_writer<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        password: Option<&str>,
    ) -> Result<()> {
        let decryptor = age::Decryptor::new(reader)
            .map_err(|e| RamzError::Backend(format!("age decrypt init: {}", e)))?;

        let mut reader = match decryptor {
            age::Decryptor::Passphrase(decryptor) => {
                let secret = password
                    .map(|p| SecretString::from(p.to_string()))
                    .ok_or_else(|| RamzError::Backend("age requires a password".into()))?;
                decryptor
                    .decrypt(&secret, None)
                    .map_err(|e| RamzError::Backend(format!("age decrypt: {}", e)))?
            }
            _ => {
                return Err(RamzError::Backend(
                    "age archive requires passphrase decryption".into(),
                ))
            }
        };

        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).map_err(RamzError::Io)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).map_err(RamzError::Io)?;
        }
        Ok(())
    }

    // Encrypt compressed payload into custom container
    // رمزنگاری payload فشرده در کانتینر سفارشی
    fn pack_custom_container(
        &self,
        compressed: &[u8],
        archive_path: &Path,
        opts: &PackOptions,
    ) -> Result<()> {
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(RAMZ_MAGIC);

        let mut flags: u8 = FLAG_ARGON2ID;
        if self.use_mlkem {
            flags |= FLAG_MLKEM;
        }
        if self.use_recipient {
            flags |= FLAG_RECIPIENT;
        }
        header.push(flags);

        header.extend_from_slice(&opts.argon2_memory_kib.to_le_bytes());
        header.extend_from_slice(&opts.argon2_iterations.to_le_bytes());
        header.extend_from_slice(&opts.argon2_parallelism.to_le_bytes());

        let salt = argon2_kdf::generate_salt();
        header.extend_from_slice(&salt);

        let mut final_key = Zeroizing::new([0u8; 32]);

        if self.use_recipient {
            let recipient_ek = self
                .recipient_key
                .as_ref()
                .ok_or_else(|| RamzError::Backend("recipient key not provided".into()))?;

            let (mlkem_ct, mlkem_shared) = mlkem_hybrid::encapsulate(recipient_ek)
                .map_err(|e| RamzError::Backend(format!("mlkem encapsulate: {}", e)))?;

            header.extend_from_slice(&(mlkem_ct.len() as u32).to_le_bytes());
            header.extend_from_slice(&mlkem_ct);

            final_key.copy_from_slice(&mlkem_shared);
        } else if self.use_mlkem {
            let password = opts
                .password
                .as_deref()
                .ok_or_else(|| RamzError::Backend("age requires a password".into()))?;

            let argon2_key = argon2_kdf::derive_key(
                password,
                &salt,
                opts.argon2_memory_kib,
                opts.argon2_iterations,
                opts.argon2_parallelism,
            )
            .map_err(|e| RamzError::Backend(format!("argon2 derive: {}", e)))?;

            let keypair = mlkem_hybrid::generate_keypair();
            let (mlkem_ct, mlkem_shared) = mlkem_hybrid::encapsulate(&keypair.public_key)
                .map_err(|e| RamzError::Backend(format!("mlkem encapsulate: {}", e)))?;

            let dk_nonce = generate_nonce();
            let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(argon2_key.as_slice()));
            let dk_encrypted = wrap_cipher
                .encrypt(Nonce::from_slice(&dk_nonce), keypair.secret_key.as_slice())
                .map_err(|e| RamzError::Backend(format!("mlkem key wrap: {}", e)))?;

            header.extend_from_slice(&(mlkem_ct.len() as u32).to_le_bytes());
            header.extend_from_slice(&mlkem_ct);
            header.extend_from_slice(&dk_nonce);
            header.extend_from_slice(&(dk_encrypted.len() as u32).to_le_bytes());
            header.extend_from_slice(&dk_encrypted);

            let combined = mlkem_hybrid::combine_secrets(argon2_key.as_slice(), &mlkem_shared);
            final_key.copy_from_slice(&combined);
        } else {
            let password = opts
                .password
                .as_deref()
                .ok_or_else(|| RamzError::Backend("age requires a password".into()))?;

            let argon2_key = argon2_kdf::derive_key(
                password,
                &salt,
                opts.argon2_memory_kib,
                opts.argon2_iterations,
                opts.argon2_parallelism,
            )
            .map_err(|e| RamzError::Backend(format!("argon2 derive: {}", e)))?;

            final_key.copy_from_slice(argon2_key.as_slice());
        }

        let payload_nonce = generate_nonce();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(final_key.as_slice()));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&payload_nonce), compressed)
            .map_err(|e| RamzError::Backend(format!("payload encrypt: {}", e)))?;

        header.extend_from_slice(&payload_nonce);
        header.extend_from_slice(&ciphertext);

        fs::write(archive_path, &header)?;
        Ok(())
    }

    // Decrypt archive to raw tar bytes, supporting all formats
    // رمزگشایی آرشیو به بایت‌های خام tar، پشتیبانی از همه فرمت‌ها
    fn decrypt_archive_to_tar(
        &self,
        archive_path: &Path,
        password: Option<&str>,
        identity: Option<&identity::Identity>,
    ) -> Result<Vec<u8>> {
        let mut file = fs::File::open(archive_path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).map_err(RamzError::Io)?;

        if raw.starts_with(RAMZ_MAGIC) {
            self.decrypt_custom_container(&raw, password, identity)
        } else {
            let mut decrypted = Vec::new();
            self.decrypt_to_writer(&mut &raw[..], &mut decrypted, password)?;
            decompress_zstd(&decrypted)
        }
    }

    // Decrypt custom RMZ1 container format
    // رمزگشایی فرمت کانتینر سفارشی RMZ1
    fn decrypt_custom_container(
        &self,
        raw: &[u8],
        password: Option<&str>,
        identity: Option<&identity::Identity>,
    ) -> Result<Vec<u8>> {
        let mut pos = RAMZ_MAGIC.len();
        let flags = *raw
            .get(pos)
            .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
        pos += 1;

        let memory_kib = read_u32(raw, &mut pos)?;
        let iterations = read_u32(raw, &mut pos)?;
        let parallelism = read_u32(raw, &mut pos)?;

        let salt = raw
            .get(pos..pos + 16)
            .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
        pos += 16;

        let mut final_key = Zeroizing::new([0u8; 32]);

        if flags & FLAG_RECIPIENT != 0 {
            let identity = identity.ok_or_else(|| {
                RamzError::Backend("recipient archive requires --identity to decrypt".into())
            })?;

            let ct_len = read_u32(raw, &mut pos)?;
            let mlkem_ct = raw
                .get(pos..pos + ct_len as usize)
                .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
            pos += ct_len as usize;

            let mlkem_shared =
                mlkem_hybrid::decapsulate(identity.decapsulation_key.as_slice(), mlkem_ct)
                    .map_err(|e| RamzError::Backend(format!("mlkem decapsulate: {}", e)))?;

            final_key.copy_from_slice(&mlkem_shared);
        } else if flags & FLAG_MLKEM != 0 {
            let password =
                password.ok_or_else(|| RamzError::Backend("age requires a password".into()))?;

            let argon2_key =
                argon2_kdf::derive_key(password, salt, memory_kib, iterations, parallelism)
                    .map_err(|e| RamzError::Backend(format!("argon2 derive: {}", e)))?;

            let ct_len = read_u32(raw, &mut pos)?;
            let mlkem_ct = raw
                .get(pos..pos + ct_len as usize)
                .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
            pos += ct_len as usize;

            let dk_nonce = raw
                .get(pos..pos + 12)
                .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
            pos += 12;

            let dk_enc_len = read_u32(raw, &mut pos)?;
            let dk_encrypted = raw
                .get(pos..pos + dk_enc_len as usize)
                .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
            pos += dk_enc_len as usize;

            let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(argon2_key.as_slice()));
            let dk_bytes = wrap_cipher
                .decrypt(Nonce::from_slice(dk_nonce), dk_encrypted)
                .map_err(|_| RamzError::Backend("wrong password or corrupted archive".into()))?;

            let mlkem_shared = mlkem_hybrid::decapsulate(&dk_bytes, mlkem_ct)
                .map_err(|e| RamzError::Backend(format!("mlkem decapsulate: {}", e)))?;

            let combined = mlkem_hybrid::combine_secrets(argon2_key.as_slice(), &mlkem_shared);
            final_key.copy_from_slice(&combined);
        } else {
            let password =
                password.ok_or_else(|| RamzError::Backend("age requires a password".into()))?;

            let argon2_key =
                argon2_kdf::derive_key(password, salt, memory_kib, iterations, parallelism)
                    .map_err(|e| RamzError::Backend(format!("argon2 derive: {}", e)))?;

            final_key.copy_from_slice(argon2_key.as_slice());
        }

        let payload_nonce = raw
            .get(pos..pos + 12)
            .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
        pos += 12;

        let ciphertext = &raw[pos..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(final_key.as_slice()));
        let compressed = cipher
            .decrypt(Nonce::from_slice(payload_nonce), ciphertext)
            .map_err(|_| RamzError::Backend("wrong password or corrupted archive".into()))?;

        decompress_zstd(&compressed)
    }

    // Extract archive to directory, with optional identity for recipient archives
    // استخراج آرشیو به پوشه، با identity اختیاری برای آرشیوهای recipient
    pub fn extract_to_dir(
        &self,
        archive_path: &Path,
        output_dir: &Path,
        password: Option<&str>,
        identity: Option<&identity::Identity>,
    ) -> Result<()> {
        let decompressed = self.decrypt_archive_to_tar(archive_path, password, identity)?;
        ramz_core::unpack_from_tar(&decompressed[..], output_dir)
    }

    // Verify archive integrity with optional identity
    // بررسی یکپارچگی آرشیو با identity اختیاری
    pub fn verify_with_identity(
        &self,
        archive_path: &Path,
        identity: &identity::Identity,
    ) -> Result<()> {
        let decompressed = self.decrypt_archive_to_tar(archive_path, None, Some(identity))?;

        let mut tar = tar::Archive::new(&decompressed[..]);
        for entry in tar
            .entries()
            .map_err(|e| RamzError::Backend(e.to_string()))?
        {
            let _ = entry.map_err(|e| RamzError::Backend(e.to_string()))?;
        }

        Ok(())
    }
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn read_u32(raw: &[u8], pos: &mut usize) -> Result<u32> {
    let bytes = raw
        .get(*pos..*pos + 4)
        .ok_or_else(|| RamzError::Backend("truncated archive header".into()))?;
    *pos += 4;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|e| RamzError::Backend(format!("zstd decoder: {}", e)))?;
    std::io::copy(&mut decoder, &mut decompressed)
        .map_err(|e| RamzError::Backend(format!("zstd decompress: {}", e)))?;
    Ok(decompressed)
}

impl Backend for AgeBackend {
    fn name(&self) -> &'static str {
        "age"
    }

    fn extension(&self) -> &'static str {
        "age.tar.zst"
    }

    fn requires_external_binary(&self) -> bool {
        false
    }

    fn pack(
        &self,
        target: &Target,
        archive_path: &Path,
        opts: &PackOptions,
        progress: &mut dyn ProgressReporter,
    ) -> Result<()> {
        if archive_path.exists() && !opts.force_overwrite {
            return Err(RamzError::ArchiveExists(archive_path.to_path_buf()));
        }

        progress.set_total(target.total_bytes);

        let temp_tar = tempfile::NamedTempFile::new()
            .map_err(|e| RamzError::Backend(format!("temp file: {}", e)))?;

        let mut tar_builder = tar::Builder::new(temp_tar.as_file());
        match target.kind {
            SourceKind::File => {
                let name = target
                    .path
                    .file_name()
                    .ok_or_else(|| RamzError::Backend("invalid file name".into()))?;
                let mut f = fs::File::open(&target.path)?;
                tar_builder.append_file(name, &mut f)?;
            }
            SourceKind::Directory => {
                let name = target
                    .path
                    .file_name()
                    .ok_or_else(|| RamzError::Backend("invalid directory name".into()))?;
                tar_builder.append_dir_all(name, &target.path)?;
            }
        }
        tar_builder.finish()?;

        let temp_tar_path = temp_tar.path();
        let mut compressed = Vec::new();
        let level = if target.kind == SourceKind::File {
            ramz_core::compression::effective_compression_level(
                &target.path,
                opts.compression_level,
            )
        } else {
            opts.compression_level
        };
        let mut encoder = zstd::stream::Encoder::new(&mut compressed, level as i32)
            .map_err(|e| RamzError::Backend(format!("zstd encoder: {}", e)))?;
        let mut f = fs::File::open(temp_tar_path)?;
        let mut buf = [0u8; 8192];
        let mut processed = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            encoder
                .write_all(&buf[..n])
                .map_err(|e| RamzError::Backend(e.to_string()))?;
            processed += n as u64;
            progress.on_progress(processed);
        }
        encoder
            .finish()
            .map_err(|e| RamzError::Backend(format!("zstd finish: {}", e)))?;

        if self.use_argon2id || self.use_mlkem || self.use_recipient {
            self.pack_custom_container(&compressed, archive_path, opts)?;
        } else {
            let encryptor = if let Some(ref pw) = opts.password {
                let secret = SecretString::from(pw.clone());
                age::Encryptor::with_user_passphrase(secret)
            } else {
                return Err(RamzError::Backend("age requires a password".into()));
            };

            let mut encrypted = fs::File::create(archive_path)?;
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| RamzError::Backend(format!("age encrypt init: {}", e)))?;
            writer
                .write_all(&compressed)
                .map_err(|e| RamzError::Backend(e.to_string()))?;
            writer
                .finish()
                .map_err(|e| RamzError::Backend(format!("age encrypt finish: {}", e)))?;
        }

        progress.finish("Archive created with age backend");
        Ok(())
    }

    fn verify(&self, archive_path: &Path, password: Option<&str>) -> Result<()> {
        let decompressed = self.decrypt_archive_to_tar(archive_path, password, None)?;

        let mut tar = tar::Archive::new(&decompressed[..]);
        for entry in tar
            .entries()
            .map_err(|e| RamzError::Backend(e.to_string()))?
        {
            let _ = entry.map_err(|e| RamzError::Backend(e.to_string()))?;
        }

        Ok(())
    }

    fn extract(
        &self,
        archive_path: &Path,
        output_dir: &Path,
        password: Option<&str>,
    ) -> Result<()> {
        self.extract_to_dir(archive_path, output_dir, password, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct NullProgress;
    impl ProgressReporter for NullProgress {
        fn set_total(&mut self, _total_bytes: u64) {}
        fn on_progress(&mut self, _processed_bytes: u64) {}
        fn finish(&mut self, _message: &str) {}
    }

    #[test]
    fn test_age_backend_file_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("secret.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello world from age").unwrap();
        let archive = tmp.path().join("secret.txt.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new();
        let opts = PackOptions {
            password: Some("test-password-123".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("test-password-123")).unwrap();
    }

    #[test]
    fn test_age_backend_directory_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("project");
        fs::create_dir(&dir).unwrap();
        let mut f = fs::File::create(dir.join("main.rs")).unwrap();
        f.write_all(b"fn main() {}").unwrap();
        let archive = tmp.path().join("project.age.tar.zst");

        let target = Target::detect(&dir).unwrap();
        let backend = AgeBackend::new();
        let opts = PackOptions {
            password: Some("dir-password-456".to_string()),
            compression_level: 9,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("dir-password-456")).unwrap();
    }

    #[test]
    fn test_age_backend_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("secret.txt");
        fs::File::create(&file).unwrap();
        let archive = tmp.path().join("secret.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new();
        let opts = PackOptions {
            password: Some("correct-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        let result = backend.verify(&archive, Some("wrong-password"));
        assert!(result.is_err());
    }

    #[test]
    fn test_age_backend_with_argon2id() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("argon2.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"argon2id test").unwrap();
        let archive = tmp.path().join("argon2.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_argon2id();
        let opts = PackOptions {
            password: Some("argon2-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("argon2-password")).unwrap();

        let extract_dir = tmp.path().join("extracted_argon2");
        backend
            .extract_to_dir(&archive, &extract_dir, Some("argon2-password"), None)
            .unwrap();
        let extracted = fs::read(extract_dir.join("argon2.txt")).unwrap();
        assert_eq!(extracted, b"argon2id test");
    }

    #[test]
    fn test_age_backend_argon2id_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("argon2.txt");
        fs::File::create(&file).unwrap();
        let archive = tmp.path().join("argon2.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_argon2id();
        let opts = PackOptions {
            password: Some("argon2-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        let result = backend.verify(&archive, Some("wrong-password"));
        assert!(result.is_err());
    }

    #[test]
    fn test_age_backend_with_mlkem() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("mlkem.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"ml-kem test").unwrap();
        let archive = tmp.path().join("mlkem.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_mlkem();
        let opts = PackOptions {
            password: Some("mlkem-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("mlkem-password")).unwrap();

        let extract_dir = tmp.path().join("extracted_mlkem");
        backend
            .extract_to_dir(&archive, &extract_dir, Some("mlkem-password"), None)
            .unwrap();
        let extracted = fs::read(extract_dir.join("mlkem.txt")).unwrap();
        assert_eq!(extracted, b"ml-kem test");
    }

    #[test]
    fn test_age_backend_mlkem_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("mlkem.txt");
        fs::File::create(&file).unwrap();
        let archive = tmp.path().join("mlkem.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_mlkem();
        let opts = PackOptions {
            password: Some("mlkem-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        let result = backend.verify(&archive, Some("wrong-password"));
        assert!(result.is_err());
    }

    #[test]
    fn test_age_backend_argon2id_custom_params() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("custom.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"custom params test").unwrap();
        let archive = tmp.path().join("custom.age.tar.zst");

        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_argon2id();
        let opts = PackOptions {
            password: Some("custom-password".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 32768,
            argon2_iterations: 2,
            argon2_parallelism: 2,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("custom-password")).unwrap();
    }

    #[test]
    fn test_age_backend_recipient_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("recipient.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"recipient-only encryption").unwrap();
        let archive = tmp.path().join("recipient.age.tar.zst");

        let identity = identity::Identity::generate();
        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_recipient(identity.encapsulation_key.clone());
        let opts = PackOptions {
            password: None,
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        let extract_dir = tmp.path().join("extracted_recipient");
        backend
            .extract_to_dir(&archive, &extract_dir, None, Some(&identity))
            .unwrap();
        let extracted = fs::read(extract_dir.join("recipient.txt")).unwrap();
        assert_eq!(extracted, b"recipient-only encryption");
    }

    #[test]
    fn test_age_backend_recipient_verify_with_identity() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("recipient.txt");
        fs::File::create(&file).unwrap();
        let archive = tmp.path().join("recipient.age.tar.zst");

        let identity = identity::Identity::generate();
        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_recipient(identity.encapsulation_key.clone());
        let opts = PackOptions {
            password: None,
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        backend.verify_with_identity(&archive, &identity).unwrap();
    }

    #[test]
    fn test_age_backend_recipient_without_identity_fails() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("recipient.txt");
        fs::File::create(&file).unwrap();
        let archive = tmp.path().join("recipient.age.tar.zst");

        let identity = identity::Identity::generate();
        let target = Target::detect(&file).unwrap();
        let backend = AgeBackend::new_with_recipient(identity.encapsulation_key.clone());
        let opts = PackOptions {
            password: None,
            compression_level: 3,
            delete_source: false,
            output_dir: Some(tmp.path().to_path_buf()),
            force_overwrite: true,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        };

        let mut progress = NullProgress;
        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        let result = backend.verify(&archive, None);
        assert!(result.is_err());
    }
}
