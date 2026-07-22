use crate::{PackOptions, RamzError, Result, SourceKind, Target};

#[derive(Debug, Clone)]
pub struct DryRunReport {
    pub source_path: std::path::PathBuf,
    pub source_kind: SourceKind,
    pub source_size: u64,
    pub estimated_archive_size: u64,
    pub compression_ratio: f64,
    pub already_compressed_files: Vec<std::path::PathBuf>,
    pub compressible_files: Vec<std::path::PathBuf>,
    pub output_path: std::path::PathBuf,
    pub backend_name: String,
    pub will_delete_source: bool,
    pub will_secure_delete: bool,
    pub password_protected: bool,
}

pub fn estimate_archive_size(
    target: &Target,
    opts: &PackOptions,
    backend_name: &str,
) -> Result<DryRunReport> {
    let mut already_compressed = Vec::new();
    let mut compressible = Vec::new();
    let mut total_already_compressed = 0u64;

    if target.kind == SourceKind::Directory {
        for entry in walkdir::WalkDir::new(&target.path) {
            let entry = entry.map_err(|e| RamzError::Backend(e.to_string()))?;
            if entry.file_type().is_file() {
                let path = entry.path();
                let size = entry
                    .metadata()
                    .map_err(|e| RamzError::Backend(e.to_string()))?
                    .len();
                if crate::compression::is_already_compressed(path) {
                    already_compressed.push(path.to_path_buf());
                    total_already_compressed += size;
                } else {
                    compressible.push(path.to_path_buf());
                }
            }
        }
    } else {
        let size = target.total_bytes;
        if crate::compression::is_already_compressed(&target.path) {
            already_compressed.push(target.path.clone());
            total_already_compressed = size;
        } else {
            compressible.push(target.path.clone());
        }
    }

    let compressible_size = target.total_bytes.saturating_sub(total_already_compressed);

    let estimated_compressed = (compressible_size as f64 * 0.4) as u64 + total_already_compressed;

    let encryption_overhead = if backend_name == "age" { 1024 } else { 512 };

    let file_count = compressible.len() + already_compressed.len();
    let tar_overhead = if target.kind == SourceKind::Directory {
        file_count as u64 * 512
    } else {
        512
    };

    let estimated_total = estimated_compressed + encryption_overhead + tar_overhead;

    let output_path = if let Some(ref out) = opts.output_dir {
        out.join(format!(
            "{}.{}",
            target
                .path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy(),
            if backend_name == "age" {
                "age.tar.zst"
            } else {
                "7z"
            }
        ))
    } else {
        target.path.with_extension(if backend_name == "age" {
            "age.tar.zst"
        } else {
            "7z"
        })
    };

    let ratio = if target.total_bytes > 0 {
        estimated_total as f64 / target.total_bytes as f64
    } else {
        1.0
    };

    Ok(DryRunReport {
        source_path: target.path.clone(),
        source_kind: target.kind,
        source_size: target.total_bytes,
        estimated_archive_size: estimated_total,
        compression_ratio: ratio,
        already_compressed_files: already_compressed,
        compressible_files: compressible,
        output_path,
        backend_name: backend_name.to_string(),
        will_delete_source: opts.delete_source,
        will_secure_delete: opts.secure_delete,
        password_protected: opts.password.is_some(),
    })
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let size = bytes as f64 / 1024f64.powi(exp as i32);
    format!("{:.2} {}", size, UNITS[exp])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_estimate_single_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = std::fs::File::create(&file).unwrap();
        f.write_all(&[0u8; 1000]).unwrap();

        let target = Target::detect(&file).unwrap();
        let opts = PackOptions::default();
        let report = estimate_archive_size(&target, &opts, "age").unwrap();

        assert_eq!(report.source_size, 1000);
        assert!(report.estimated_archive_size > 0);
        assert!(report.estimated_archive_size < 2000);
        assert!(!report.password_protected);
        assert!(!report.will_secure_delete);
    }

    #[test]
    fn test_estimate_with_compressed_files() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("mixed");
        std::fs::create_dir(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("text.txt")).unwrap();
        f.write_all(&[0u8; 1000]).unwrap();
        let mut f = std::fs::File::create(dir.join("photo.jpg")).unwrap();
        f.write_all(&[0u8; 5000]).unwrap();

        let target = Target::detect(&dir).unwrap();
        let opts = PackOptions::default();
        let report = estimate_archive_size(&target, &opts, "age").unwrap();

        assert_eq!(report.already_compressed_files.len(), 1);
        assert_eq!(report.compressible_files.len(), 1);
        assert_eq!(report.source_size, 6000);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_estimate_with_secure_delete() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        let mut f = std::fs::File::create(&file).unwrap();
        f.write_all(&[0u8; 1000]).unwrap();

        let target = Target::detect(&file).unwrap();
        let opts = PackOptions {
            secure_delete: true,
            ..Default::default()
        };
        let report = estimate_archive_size(&target, &opts, "age").unwrap();

        assert!(report.will_secure_delete);
    }
}
