use std::fs::File;
use std::io::Write;
use std::path::Path;

use age::secrecy::Secret;
use ramz_core::{
    pack_to_tar, unpack_from_tar, Backend, PackOptions, ProgressReporter, RamzError, Result, Target,
};

pub struct AgeBackend;

struct CountingWriter<'a, W: Write> {
    inner: W,
    written: u64,
    progress: &'a mut dyn ProgressReporter,
}

impl<'a, W: Write> Write for CountingWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        self.progress.on_progress(self.written);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Backend for AgeBackend {
    fn name(&self) -> &'static str {
        "age"
    }

    fn extension(&self) -> &'static str {
        "ramz-age"
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
        progress.set_total(target.total_bytes);

        let password = opts
            .password
            .clone()
            .ok_or_else(|| RamzError::Backend("age backend requires a password".into()))?;

        let out_file = File::create(archive_path)?;

        let encryptor = age::Encryptor::with_user_passphrase(Secret::new(password));
        let age_writer = encryptor
            .wrap_output(out_file)
            .map_err(|e| RamzError::Backend(format!("age encryption init failed: {e}")))?;

        let compression_level = opts.compression_level.clamp(1, 22) as i32;
        let mut zstd_writer = zstd::stream::Encoder::new(age_writer, compression_level)
            .map_err(|e| RamzError::Backend(format!("zstd init failed: {e}")))?;

        {
            let mut counting = CountingWriter {
                inner: &mut zstd_writer,
                written: 0,
                progress,
            };
            pack_to_tar(target, &mut counting)?;
        }

        let age_writer = zstd_writer
            .finish()
            .map_err(|e| RamzError::Backend(format!("zstd finish failed: {e}")))?;
        age_writer
            .finish()
            .map_err(|e| RamzError::Backend(format!("age finish failed: {e}")))?;

        progress.finish("age encryption complete");
        Ok(())
    }

    fn verify(&self, archive_path: &Path, password: Option<&str>) -> Result<()> {
        let password = password.ok_or_else(|| {
            RamzError::Backend("age backend requires a password to verify".into())
        })?;

        let in_file = File::open(archive_path)?;
        let decryptor = match age::Decryptor::new(in_file)
            .map_err(|e| RamzError::VerificationFailed(e.to_string()))?
        {
            age::Decryptor::Passphrase(d) => d,
            _ => {
                return Err(RamzError::VerificationFailed(
                    "unexpected age recipient type".into(),
                ))
            }
        };

        let reader = decryptor
            .decrypt(&Secret::new(password.to_string()), None)
            .map_err(|e| RamzError::VerificationFailed(e.to_string()))?;

        let zstd_reader = zstd::stream::Decoder::new(reader)
            .map_err(|e| RamzError::VerificationFailed(format!("zstd decode init failed: {e}")))?;

        let tmp = tempfile::tempdir()
            .map_err(|e| RamzError::Backend(format!("failed to create temp dir: {e}")))?;
        unpack_from_tar(zstd_reader, tmp.path())
            .map_err(|e| RamzError::VerificationFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramz_core::{NullProgress, PackOptions, Target};
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_age_backend_name() {
        let backend = AgeBackend;
        assert_eq!(backend.name(), "age");
        assert_eq!(backend.extension(), "ramz-age");
        assert!(!backend.requires_external_binary());
    }

    #[test]
    fn test_age_pack_and_verify() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.txt");
        let mut f = std::fs::File::create(&source).unwrap();
        f.write_all(b"hello world from age test").unwrap();

        let target = Target::detect(&source).unwrap();
        let archive = tmp.path().join("test.ramz-age");

        let backend = AgeBackend;
        let mut progress = NullProgress;
        let opts = PackOptions {
            password: Some("testpassword123".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: None,
            force_overwrite: false,
        };

        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();
        assert!(archive.exists());

        backend.verify(&archive, Some("testpassword123")).unwrap();
    }

    #[test]
    fn test_age_verify_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.txt");
        let mut f = std::fs::File::create(&source).unwrap();
        f.write_all(b"hello world").unwrap();

        let target = Target::detect(&source).unwrap();
        let archive = tmp.path().join("test.ramz-age");

        let backend = AgeBackend;
        let mut progress = NullProgress;
        let opts = PackOptions {
            password: Some("correctpassword".to_string()),
            compression_level: 3,
            delete_source: false,
            output_dir: None,
            force_overwrite: false,
        };

        backend
            .pack(&target, &archive, &opts, &mut progress)
            .unwrap();

        let result = backend.verify(&archive, Some("wrongpassword"));
        assert!(result.is_err());
    }

    #[test]
    fn test_age_pack_no_password() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.txt");
        std::fs::File::create(&source).unwrap();

        let target = Target::detect(&source).unwrap();
        let archive = tmp.path().join("test.ramz-age");

        let backend = AgeBackend;
        let mut progress = NullProgress;
        let opts = PackOptions {
            password: None,
            compression_level: 3,
            delete_source: false,
            output_dir: None,
            force_overwrite: false,
        };

        let result = backend.pack(&target, &archive, &opts, &mut progress);
        assert!(matches!(result, Err(RamzError::Backend(_))));
    }
}
