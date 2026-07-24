use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{RamzError, Result};

// State saved during an interrupted pack operation for resume
// وضعیت ذخیره شده در حین عملیات pack ناتمام برای ادامه
#[derive(Debug, Clone)]
pub struct ResumeState {
    pub source_path: PathBuf,
    pub archive_path: PathBuf,
    pub backend_name: String,
    pub total_bytes: u64,
    pub processed_bytes: u64,
    pub checksum: String,
    pub password_hint: Option<String>,
    pub created_at: String,
}

// Compute SHA-256 checksum of a file or directory
// محاسبه چک‌سام SHA-256 یک فایل یا پوشه
pub fn compute_file_checksum(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    if path.is_file() {
        let mut file = fs::File::open(path)?;
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    } else if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();
        for entry in entries {
            if entry.is_file() {
                let mut file = fs::File::open(&entry)?;
                let mut buf = [0u8; 8192];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
            }
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// Check if an archive has a corresponding resume state
// بررسی اینکه آیا آرشیو یک وضعیت resume مربوطه دارد
pub fn is_resumable(archive_path: &Path) -> bool {
    let state_path = resume_state_path(archive_path);
    state_path.exists()
}

// Load resume state for an archive if it exists
// بارگذاری وضعیت resume برای یک آرشیو اگر وجود داشته باشد
pub fn load_resume_state(archive_path: &Path) -> Result<Option<ResumeState>> {
    let state_path = resume_state_path(archive_path);
    if !state_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&state_path)
        .map_err(|e| RamzError::Backend(format!("read resume state: {}", e)))?;

    let parts: Vec<&str> = content.trim().split('\n').collect();
    if parts.len() < 6 {
        return Err(RamzError::ResumeMismatch("corrupted resume state".into()));
    }

    Ok(Some(ResumeState {
        source_path: PathBuf::from(parts[0]),
        archive_path: PathBuf::from(parts[1]),
        backend_name: parts[2].to_string(),
        total_bytes: parts[3].parse().unwrap_or(0),
        processed_bytes: parts[4].parse().unwrap_or(0),
        checksum: parts[5].to_string(),
        password_hint: parts.get(6).map(|s| s.to_string()),
        created_at: parts.get(7).unwrap_or(&"").to_string(),
    }))
}

// Save resume state alongside the archive
// ذخیره وضعیت resume در کنار آرشیو
pub fn save_resume_state(state: &ResumeState, archive_path: &Path) -> Result<()> {
    let state_path = resume_state_path(archive_path);
    let content = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        state.source_path.display(),
        state.archive_path.display(),
        state.backend_name,
        state.total_bytes,
        state.processed_bytes,
        state.checksum,
        state.password_hint.as_deref().unwrap_or(""),
        state.created_at,
    );
    fs::write(&state_path, content)?;
    Ok(())
}

// Remove resume state after successful completion
// حذف وضعیت resume پس از تکمیل موفق
pub fn remove_resume_state(archive_path: &Path) -> Result<()> {
    let state_path = resume_state_path(archive_path);
    if state_path.exists() {
        fs::remove_file(&state_path)?;
    }
    Ok(())
}

// Verify that source hasn't changed since resume state was created
// بررسی اینکه منبع از زمان ساخت وضعیت resume تغییر نکرده
pub fn verify_source_unchanged(state: &ResumeState) -> Result<bool> {
    let current_checksum = compute_file_checksum(&state.source_path)?;
    Ok(current_checksum == state.checksum && state.processed_bytes == state.total_bytes)
}

// Get the path to the resume state file for a given archive
// گرفتن مسیر فایل وضعیت resume برای یک آرشیو داده شده
fn resume_state_path(archive_path: &Path) -> PathBuf {
    archive_path.with_extension("resume")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_compute_file_checksum() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"hello").unwrap();
        let checksum1 = compute_file_checksum(&file).unwrap();
        let checksum2 = compute_file_checksum(&file).unwrap();
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_resume_state_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.age.tar.zst");
        fs::File::create(&archive).unwrap();

        let state = ResumeState {
            source_path: PathBuf::from("/source"),
            archive_path: archive.clone(),
            backend_name: "age".to_string(),
            total_bytes: 1000,
            processed_bytes: 500,
            checksum: "abc123".to_string(),
            password_hint: None,
            created_at: "now".to_string(),
        };

        save_resume_state(&state, &archive).unwrap();
        assert!(is_resumable(&archive));

        let loaded = load_resume_state(&archive).unwrap().unwrap();
        assert_eq!(loaded.total_bytes, 1000);
        assert_eq!(loaded.processed_bytes, 500);

        remove_resume_state(&archive).unwrap();
        assert!(!is_resumable(&archive));
    }

    #[test]
    fn test_verify_source_unchanged() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"hello").unwrap();

        let checksum = compute_file_checksum(&file).unwrap();
        let state = ResumeState {
            source_path: file.clone(),
            archive_path: tmp.path().join("archive.age.tar.zst"),
            backend_name: "age".to_string(),
            total_bytes: 5,
            processed_bytes: 5,
            checksum,
            password_hint: None,
            created_at: "now".to_string(),
        };

        assert!(verify_source_unchanged(&state).unwrap());

        fs::write(&file, b"changed").unwrap();
        assert!(!verify_source_unchanged(&state).unwrap());
    }

    #[test]
    fn test_resume_does_not_falsely_report_completion() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("source.txt");
        fs::write(&file, b"hello").unwrap();
        let archive = tmp.path().join("test.age.tar.zst");

        let state = ResumeState {
            source_path: file,
            archive_path: archive.clone(),
            backend_name: "age".to_string(),
            total_bytes: 5,
            processed_bytes: 5,
            checksum: "abc".to_string(),
            password_hint: None,
            created_at: "now".to_string(),
        };
        save_resume_state(&state, &archive).unwrap();

        let loaded = load_resume_state(&archive).unwrap().unwrap();
        assert!(!archive.exists());
        assert!(loaded.processed_bytes == loaded.total_bytes);
    }
}
