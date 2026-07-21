use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{RamzError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

const RESUME_EXTENSION: &str = ".ramz-resume";

pub fn resume_file_path(archive_path: &Path) -> PathBuf {
    let mut resume_path = archive_path.as_os_str().to_os_string();
    resume_path.push(RESUME_EXTENSION);
    PathBuf::from(resume_path)
}

pub fn save_resume_state(state: &ResumeState, archive_path: &Path) -> Result<()> {
    let resume_path = resume_file_path(archive_path);
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| RamzError::Backend(format!("serialize resume state: {}", e)))?;
    fs::write(&resume_path, json).map_err(RamzError::Io)?;
    Ok(())
}

pub fn load_resume_state(archive_path: &Path) -> Result<Option<ResumeState>> {
    let resume_path = resume_file_path(archive_path);
    if !resume_path.exists() {
        return Ok(None);
    }
    let json = fs::read_to_string(&resume_path).map_err(RamzError::Io)?;
    let state: ResumeState = serde_json::from_str(&json)
        .map_err(|e| RamzError::Backend(format!("deserialize resume state: {}", e)))?;
    Ok(Some(state))
}

pub fn remove_resume_state(archive_path: &Path) -> Result<()> {
    let resume_path = resume_file_path(archive_path);
    if resume_path.exists() {
        fs::remove_file(&resume_path).map_err(RamzError::Io)?;
    }
    Ok(())
}

pub fn is_resumable(archive_path: &Path) -> bool {
    resume_file_path(archive_path).exists()
}

pub fn compute_file_checksum(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path).map_err(RamzError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer).map_err(RamzError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn verify_source_unchanged(state: &ResumeState) -> Result<bool> {
    if !state.source_path.exists() {
        return Ok(false);
    }
    let current_checksum = compute_file_checksum(&state.source_path)?;
    Ok(current_checksum == state.checksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_resume_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.age.tar.zst");
        let state = ResumeState {
            source_path: tmp.path().join("source"),
            archive_path: archive.clone(),
            backend_name: "age".to_string(),
            total_bytes: 1024,
            processed_bytes: 512,
            checksum: "abc123".to_string(),
            password_hint: Some("hint".to_string()),
            created_at: "2024-01-01".to_string(),
        };

        save_resume_state(&state, &archive).unwrap();
        let loaded = load_resume_state(&archive).unwrap().unwrap();
        assert_eq!(loaded.total_bytes, 1024);
        assert_eq!(loaded.processed_bytes, 512);
        assert_eq!(loaded.backend_name, "age");

        remove_resume_state(&archive).unwrap();
        assert!(!is_resumable(&archive));
    }

    #[test]
    fn test_missing_resume_returns_none() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("nonexistent.age.tar.zst");
        let result = load_resume_state(&archive).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_compute_checksum() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"hello").unwrap();

        let checksum1 = compute_file_checksum(&file).unwrap();
        let checksum2 = compute_file_checksum(&file).unwrap();
        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum1.len(), 64);
    }

    #[test]
    fn test_verify_source_unchanged() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("source.txt");
        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"content").unwrap();

        let checksum = compute_file_checksum(&file).unwrap();
        let state = ResumeState {
            source_path: file.clone(),
            archive_path: tmp.path().join("out.age.tar.zst"),
            backend_name: "age".to_string(),
            total_bytes: 7,
            processed_bytes: 7,
            checksum,
            password_hint: None,
            created_at: "2024-01-01".to_string(),
        };

        assert!(verify_source_unchanged(&state).unwrap());

        let mut f = fs::File::create(&file).unwrap();
        f.write_all(b"modified").unwrap();
        assert!(!verify_source_unchanged(&state).unwrap());
    }
}
