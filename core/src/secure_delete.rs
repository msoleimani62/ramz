use std::fs;
use std::io::{Seek, Write};
use std::path::Path;

use crate::Result;

// اندازه‌ی بافر برای نوشتن هر بلوک در طول overwrite
// buffer size used for each write chunk during overwrite
const CHUNK_SIZE: usize = 8192;

// حذف امن یک فایل با بازنویسی محتواش قبل از حذف واقعی (۳ pass: صفر، یک،
// تصادفی - هرکدوم تکرار می‌شه).
//
// ⚠️ هشدار صادقانه: این تضمین فیزیکی نیست. روی SSD/فلش با wear-leveling،
// کنترلر درایو ممکنه واقعاً همون بلاک فیزیکی رو دوباره ننویسه (چون
// نگاشت منطقی-به-فیزیکی داخلی داره) - یعنی داده‌ی قدیمی می‌تونه هنوز
// جایی روی فلش باقی بمونه. این تابع فقط بازیابی از طریق ابزارهای معمول
// فایل‌سیستمی/forensic سطح‌پایین رو سخت‌تر می‌کنه، نه غیرممکن روی همه‌ی
// سخت‌افزارها. برای HDDهای سنتی (بدون wear-leveling)، این روش مؤثرتره.
//
// securely deletes a file by overwriting its content before actual removal
// (3 passes: zeros, ones, random - each repeated).
//
// ⚠️ honest warning: this is not a physical guarantee. On SSDs/flash drives
// with wear-leveling, the drive controller may not actually rewrite the
// same physical block (due to internal logical-to-physical remapping) -
// meaning old data could still persist somewhere on the flash. This
// function only makes recovery via common filesystem/low-level forensic
// tools harder, not impossible on all hardware. For traditional HDDs
// (without wear-leveling), this method is more effective.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    let size = metadata.len() as usize;

    let mut file = fs::OpenOptions::new().write(true).open(path)?;

    let zeros = vec![0u8; CHUNK_SIZE];
    let ones = vec![0xFFu8; CHUNK_SIZE];

    for _ in 0..3 {
        overwrite_pass(&mut file, size, &zeros)?;
        overwrite_pass(&mut file, size, &ones)?;
        overwrite_random_pass(&mut file, size)?;
    }

    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

// یک pass از بازنویسی کل فایل با یه الگوی ثابت (صفر یا یک)
// one overwrite pass across the whole file with a fixed pattern (zeros or ones)
fn overwrite_pass(file: &mut fs::File, size: usize, pattern: &[u8]) -> Result<()> {
    file.set_len(0)?;
    file.set_len(size as u64)?;
    file.rewind()?;
    let mut written = 0usize;
    while written < size {
        let to_write = (size - written).min(pattern.len());
        file.write_all(&pattern[..to_write])?;
        written += to_write;
    }
    file.sync_all()?;
    Ok(())
}

// یک pass از بازنویسی کل فایل با داده‌ی تصادفی
// one overwrite pass across the whole file with random data
fn overwrite_random_pass(file: &mut fs::File, size: usize) -> Result<()> {
    file.set_len(0)?;
    file.set_len(size as u64)?;
    file.rewind()?;
    let mut written = 0usize;
    while written < size {
        let to_write = (size - written).min(CHUNK_SIZE);
        let random: Vec<u8> = (0..to_write).map(|_| rand::random::<u8>()).collect();
        file.write_all(&random)?;
        written += to_write;
    }
    file.sync_all()?;
    Ok(())
}

// حذف امن بازگشتی یک پوشه: تک‌تک فایل‌های داخلش (شامل زیرپوشه‌ها) رو
// قبل از حذف نهایی overwrite می‌کنه - نه فقط یه remove_dir_all ساده
// recursively secure-deletes a directory: overwrites every file inside it
// (including subdirectories) before final removal - not just a plain
// remove_dir_all
fn secure_delete_dir(dir: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir).contents_first(true).into_iter() {
        let entry = entry
            .map_err(|e| crate::RamzError::SecureDelete(format!("directory walk failed: {}", e)))?;
        let path = entry.path();
        if path.is_file() {
            secure_delete_file(path)?;
        } else if path.is_dir() && path != dir {
            fs::remove_dir(path)?;
        }
    }
    fs::remove_dir_all(dir)?;
    Ok(())
}

// حذف یک مسیر (فایل یا پوشه)، با امکان استفاده از حذف امن.
// برای پوشه‌ها، secure=true یعنی همه‌ی فایل‌های داخلش هم امن پاک می‌شن،
// نه فقط خودِ پوشه
// deletes a path (file or directory), optionally using secure deletion.
// for directories, secure=true means every file inside is also securely
// wiped, not just the directory entry itself
pub fn delete_path(path: &Path, secure: bool) -> Result<()> {
    if path.is_file() {
        if secure {
            secure_delete_file(path)?;
        } else {
            fs::remove_file(path)?;
        }
    } else if path.is_dir() {
        if secure {
            secure_delete_dir(path)?;
        } else {
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_delete_path_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"hello").unwrap();
        delete_path(&file, false).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_delete_path_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file.txt"), b"hello").unwrap();
        delete_path(&dir, false).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_secure_delete_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("secret.txt");
        fs::write(&file, b"top secret data that must be destroyed").unwrap();
        secure_delete_file(&file).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_secure_delete_empty_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("empty.txt");
        fs::write(&file, b"").unwrap();
        secure_delete_file(&file).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_secure_delete_large_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("large.bin");
        let data = vec![0x42u8; 500_000];
        fs::write(&file, &data).unwrap();
        secure_delete_file(&file).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_secure_delete_dir_recursive() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("nested");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"file a").unwrap();
        let sub = dir.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("b.txt"), b"file b").unwrap();

        delete_path(&dir, true).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_delete_nonexistent_path_is_noop() {
        let tmp = TempDir::new().unwrap();
        let ghost = tmp.path().join("does_not_exist.txt");
        // نباید panic کنه یا خطای غیرمنتظره بده - مسیری که وجود نداره
        // رو باید بی‌صدا نادیده بگیره
        // must not panic or error unexpectedly - a nonexistent path should
        // be silently ignored
        assert!(delete_path(&ghost, false).is_ok());
        assert!(delete_path(&ghost, true).is_ok());
    }
}
