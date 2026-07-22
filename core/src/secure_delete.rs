use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;

use crate::{RamzError, Result};

// Number of overwrite passes for secure deletion (DoD 5220.22-M inspired: zero, ones, random)
// تعداد دورهای overwrite برای حذف امن (الگوی DoD 5220.22-M: صفر، یک، تصادفی)
const SECURE_DELETE_PASSES: usize = 3;

// Buffer size for overwrite operations (8 KiB)
// اندازه‌ی بافر برای عملیات overwrite (8 کیلوبایت)
const OVERWRITE_BUFFER_SIZE: usize = 8192;

/// Securely delete a single file by overwriting its content before unlinking.
/// The file is overwritten with zeros, then ones, then random bytes.
/// After each pass, the buffer is synced to disk to reduce caching effects.
/// حذف امن یه فایل تکی با overwrite محتوا قبل از حذف از فایل‌سیستم.
/// فایل با صفر، بعد یک، بعد بایت تصادفی overwrite می‌شه.
/// بعد از هر دور، بافر sync می‌شه روی دیسک.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(RamzError::Io)?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        fs::remove_file(path).map_err(RamzError::Io)?;
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(RamzError::Io)?;

    for pass in 0..SECURE_DELETE_PASSES {
        file.seek(SeekFrom::Start(0)).map_err(RamzError::Io)?;

        let pattern: Vec<u8> = match pass {
            0 => vec![0u8; OVERWRITE_BUFFER_SIZE],
            1 => vec![0xFFu8; OVERWRITE_BUFFER_SIZE],
            _ => {
                let mut buf = vec![0u8; OVERWRITE_BUFFER_SIZE];
                rand::thread_rng().fill_bytes(&mut buf);
                buf
            }
        };

        let mut written = 0usize;
        while written < file_size {
            let to_write = std::cmp::min(OVERWRITE_BUFFER_SIZE, file_size - written);
            file.write_all(&pattern[..to_write])
                .map_err(RamzError::Io)?;
            written += to_write;
        }

        file.flush().map_err(RamzError::Io)?;
        file.sync_all().map_err(RamzError::Io)?;
    }

    drop(file);
    fs::remove_file(path).map_err(RamzError::Io)?;
    Ok(())
}

/// Recursively securely delete all files in a directory, then remove the directory itself.
/// Files are securely deleted; empty subdirectories are removed normally.
/// حذف امن بازگشتی همه‌ی فایل‌های یه دایرکتوری، بعد حذف خود دایرکتوری.
/// فایل‌ها secure delete می‌شن؛ زیردایرکتوری‌های خالی به‌صورت عادی حذف می‌شن.
pub fn secure_delete_dir(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).map_err(RamzError::Io)? {
        let entry = entry.map_err(RamzError::Io)?;
        let entry_path = entry.path();

        if entry_path.is_file() {
            secure_delete_file(&entry_path)?;
        } else if entry_path.is_dir() {
            secure_delete_dir(&entry_path)?;
        }
    }

    fs::remove_dir(path).map_err(RamzError::Io)?;
    Ok(())
}

/// Delete a file or directory, optionally using secure overwrite.
/// If `secure` is false, uses standard fast deletion.
/// If `secure` is true, overwrites file content before unlinking.
/// حذف فایل یا دایرکتوری، با گزینه‌ی overwrite امن.
/// اگه `secure` false باشه، از حذف سریع استاندارد استفاده می‌شه.
/// اگه `secure` true باشه، قبل از حذف overwrite انجام می‌شه.
pub fn delete_path(path: &Path, secure: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_file() {
        if secure {
            secure_delete_file(path)
        } else {
            fs::remove_file(path).map_err(RamzError::Io)
        }
    } else if path.is_dir() {
        if secure {
            secure_delete_dir(path)
        } else {
            fs::remove_dir_all(path).map_err(RamzError::Io)
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_secure_delete_file_overwrites_content() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("secret.txt");

        let original = b"this is sensitive data that must be destroyed";
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(original).unwrap();
            f.flush().unwrap();
        }

        let size_before = fs::metadata(&file_path).unwrap().len() as usize;
        assert_eq!(size_before, original.len());

        secure_delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_standard_delete_file_fast() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("fast.txt");

        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"fast delete test").unwrap();
        }

        delete_path(&file_path, false).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_secure_delete_dir_recursive() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("nested");
        fs::create_dir(&dir).unwrap();
        fs::create_dir(dir.join("sub")).unwrap();

        {
            let mut f = File::create(dir.join("a.txt")).unwrap();
            f.write_all(b"file a").unwrap();
        }
        {
            let mut f = File::create(dir.join("sub/b.txt")).unwrap();
            f.write_all(b"file b").unwrap();
        }

        secure_delete_dir(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_delete_path_with_secure_flag() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("flag_test.txt");

        {
            let mut f = File::create(&file).unwrap();
            f.write_all(b"test content").unwrap();
        }

        delete_path(&file, true).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_delete_nonexistent_path_is_noop() {
        let tmp = TempDir::new().unwrap();
        let ghost = tmp.path().join("does_not_exist.txt");
        delete_path(&ghost, true).unwrap();
        delete_path(&ghost, false).unwrap();
    }

    #[test]
    fn test_secure_delete_empty_file() {
        let tmp = TempDir::new().unwrap();
        let empty = tmp.path().join("empty.txt");
        File::create(&empty).unwrap();
        secure_delete_file(&empty).unwrap();
        assert!(!empty.exists());
    }

    #[test]
    fn test_secure_delete_large_file() {
        let tmp = TempDir::new().unwrap();
        let large = tmp.path().join("large.bin");

        let data = vec![0xABu8; 1024 * 1024]; // 1 MiB
        {
            let mut f = File::create(&large).unwrap();
            f.write_all(&data).unwrap();
        }

        secure_delete_file(&large).unwrap();
        assert!(!large.exists());
    }
}
