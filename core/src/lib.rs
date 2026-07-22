use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod compression;
pub use compression::*;
pub mod dry_run;
pub use dry_run::*;
pub mod resume;
pub use resume::*;
pub mod secure_delete;
pub use secure_delete::*;

#[derive(Error, Debug)]
pub enum RamzError {
    #[error("path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("source is empty: {0}")]
    EmptySource(PathBuf),

    #[error("archive already exists: {0}")]
    ArchiveExists(PathBuf),

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("empty password not allowed")]
    EmptyPassword,

    #[error("backend engine error: {0}")]
    Backend(String),

    #[error("integrity verification failed: {0}")]
    VerificationFailed(String),

    #[error("resume state mismatch: {0}")]
    ResumeMismatch(String),

    #[error("dry run aborted")]
    DryRunAborted,

    #[error("incompatible backend flag: {0}")]
    IncompatibleFlag(String),

    #[error("secure delete failed: {0}")]
    SecureDelete(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RamzError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File,
    Directory,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub path: PathBuf,
    pub kind: SourceKind,
    pub total_bytes: u64,
}

impl Target {
    pub fn detect(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(RamzError::PathNotFound(path.to_path_buf()));
        }

        let kind = if path.is_dir() {
            SourceKind::Directory
        } else {
            SourceKind::File
        };

        if kind == SourceKind::Directory {
            let empty = fs::read_dir(path)?.next().is_none();
            if empty {
                return Err(RamzError::EmptySource(path.to_path_buf()));
            }
        }

        let total_bytes = dir_size(path)?;

        Ok(Target {
            path: path.to_path_buf(),
            kind,
            total_bytes,
        })
    }
}

pub fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry.map_err(|e| RamzError::Backend(e.to_string()))?;
        if entry.file_type().is_file() {
            total += entry
                .metadata()
                .map_err(|e| RamzError::Backend(e.to_string()))?
                .len();
        }
    }
    Ok(total)
}

pub trait ProgressReporter: Send {
    fn set_total(&mut self, total_bytes: u64);
    fn on_progress(&mut self, processed_bytes: u64);
    fn finish(&mut self, message: &str);
}

pub struct NullProgress;
impl ProgressReporter for NullProgress {
    fn set_total(&mut self, _total_bytes: u64) {}
    fn on_progress(&mut self, _processed_bytes: u64) {}
    fn finish(&mut self, _message: &str) {}
}

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub password: Option<String>,
    pub compression_level: u8,
    pub delete_source: bool,
    pub output_dir: Option<PathBuf>,
    pub force_overwrite: bool,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub secure_delete: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            password: None,
            compression_level: 9,
            delete_source: false,
            output_dir: None,
            force_overwrite: false,
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            secure_delete: false,
        }
    }
}

pub trait Backend {
    fn name(&self) -> &'static str;
    fn extension(&self) -> &'static str;
    fn requires_external_binary(&self) -> bool;

    fn pack(
        &self,
        target: &Target,
        archive_path: &Path,
        opts: &PackOptions,
        progress: &mut dyn ProgressReporter,
    ) -> Result<()>;

    fn verify(&self, archive_path: &Path, password: Option<&str>) -> Result<()>;
}

pub fn pack_to_tar<W: Write>(target: &Target, writer: W) -> Result<()> {
    let mut builder = tar::Builder::new(writer);
    match target.kind {
        SourceKind::File => {
            let name = target
                .path
                .file_name()
                .ok_or_else(|| RamzError::Backend("invalid file name".into()))?;
            let mut f = fs::File::open(&target.path)?;
            builder.append_file(name, &mut f)?;
        }
        SourceKind::Directory => {
            let name = target
                .path
                .file_name()
                .ok_or_else(|| RamzError::Backend("invalid directory name".into()))?;
            builder.append_dir_all(name, &target.path)?;
        }
    }
    builder.finish()?;
    Ok(())
}

pub fn unpack_from_tar<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.unpack(dest)?;
    Ok(())
}

pub fn read_and_confirm_password(
    read1: impl FnOnce() -> std::io::Result<String>,
    read2: impl FnOnce() -> std::io::Result<String>,
) -> Result<String> {
    let p1 = read1()?;
    let p2 = read2()?;
    if p1 != p2 {
        return Err(RamzError::PasswordMismatch);
    }
    if p1.is_empty() {
        return Err(RamzError::EmptyPassword);
    }
    Ok(p1)
}

pub fn safe_output_dir(path: &Path, explicit_output: Option<&Path>) -> PathBuf {
    if let Some(out) = explicit_output {
        return out.to_path_buf();
    }
    path.parent()
        .filter(|p| {
            let s = p.as_os_str();
            !s.is_empty() && s != "/"
        })
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_dir_size_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello world").unwrap();
        assert_eq!(dir_size(&file).unwrap(), 11);
    }

    #[test]
    fn test_dir_size_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir).unwrap();
        let file = dir.join("test.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello world").unwrap();
        assert_eq!(dir_size(&dir).unwrap(), 11);
    }

    #[test]
    fn test_target_detect_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        fs::File::create(&file).unwrap();
        let target = Target::detect(&file).unwrap();
        assert_eq!(target.kind, SourceKind::File);
        assert_eq!(target.total_bytes, 0);
    }

    #[test]
    fn test_target_detect_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir).unwrap();
        let file = dir.join("test.txt");
        fs::File::create(&file).unwrap();
        let target = Target::detect(&dir).unwrap();
        assert_eq!(target.kind, SourceKind::Directory);
        assert_eq!(target.total_bytes, 0);
    }

    #[test]
    fn test_target_detect_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("empty");
        fs::create_dir(&dir).unwrap();
        assert!(matches!(
            Target::detect(&dir),
            Err(RamzError::EmptySource(_))
        ));
    }

    #[test]
    fn test_target_detect_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent");
        assert!(matches!(
            Target::detect(&path),
            Err(RamzError::PathNotFound(_))
        ));
    }

    #[test]
    fn test_read_and_confirm_password_match() {
        let result =
            read_and_confirm_password(|| Ok("password".to_string()), || Ok("password".to_string()));
        assert_eq!(result.unwrap(), "password");
    }

    #[test]
    fn test_read_and_confirm_password_mismatch() {
        let result = read_and_confirm_password(
            || Ok("password1".to_string()),
            || Ok("password2".to_string()),
        );
        assert!(matches!(result, Err(RamzError::PasswordMismatch)));
    }

    #[test]
    fn test_read_and_confirm_password_empty() {
        let result = read_and_confirm_password(|| Ok("".to_string()), || Ok("".to_string()));
        assert!(matches!(result, Err(RamzError::EmptyPassword)));
    }

    #[test]
    fn test_safe_output_dir_with_explicit() {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("output");
        let result = safe_output_dir(Path::new("/some/file.txt"), Some(&out));
        assert_eq!(result, out);
    }

    #[test]
    fn test_safe_output_dir_from_file() {
        let result = safe_output_dir(Path::new("/some/file.txt"), None);
        assert_eq!(result, Path::new("/some"));
    }

    #[test]
    fn test_safe_output_dir_from_root() {
        let result = safe_output_dir(Path::new("/file.txt"), None);
        assert_eq!(result, Path::new("."));
    }

    #[test]
    fn test_pack_to_tar_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello").unwrap();

        let target = Target::detect(&file).unwrap();
        let mut buf = Vec::new();
        pack_to_tar(&target, &mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_pack_to_tar_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("project");
        fs::create_dir(&dir).unwrap();
        let mut f = fs::File::create(dir.join("main.rs")).unwrap();
        f.write_all(b"fn main() {}").unwrap();

        let target = Target::detect(&dir).unwrap();
        let mut buf = Vec::new();
        pack_to_tar(&target, &mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_unpack_from_tar() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello").unwrap();

        let target = Target::detect(&file).unwrap();
        let mut buf = Vec::new();
        pack_to_tar(&target, &mut buf).unwrap();

        let extract_dir = tmp.path().join("extracted");
        fs::create_dir(&extract_dir).unwrap();
        unpack_from_tar(&buf[..], &extract_dir).unwrap();

        let extracted = extract_dir.join("test.txt");
        assert!(extracted.exists());
        let content = fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "hello");
    }
}
