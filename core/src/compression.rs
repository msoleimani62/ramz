use std::path::Path;

// Determine effective compression level based on file content type
// تعیین سطح فشرده‌سازی مؤثر بر اساس نوع محتوای فایل
pub fn effective_compression_level(path: &Path, requested: u8) -> u8 {
    if is_already_compressed(path) {
        1
    } else {
        requested.clamp(1, 22)
    }
}

// Check if a file is already compressed (store-only for these types)
// بررسی اینکه آیا فایل قبلاً فشرده شده (فقط ذخیره برای این نوع‌ها)
pub fn is_already_compressed(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    matches!(
        ext.as_str(),
        "zip"
            | "gz"
            | "bz2"
            | "xz"
            | "7z"
            | "rar"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "mp3"
            | "mp4"
            | "ogg"
            | "webm"
            | "pdf"
            | "docx"
            | "xlsx"
            | "pptx"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_already_compressed_png() {
        assert!(is_already_compressed(Path::new("image.png")));
    }

    #[test]
    fn test_is_already_compressed_txt() {
        assert!(!is_already_compressed(Path::new("file.txt")));
    }

    #[test]
    fn test_effective_compression_level_for_compressed() {
        let level = effective_compression_level(Path::new("image.png"), 9);
        assert_eq!(level, 1);
    }

    #[test]
    fn test_effective_compression_level_for_text() {
        let level = effective_compression_level(Path::new("file.txt"), 9);
        assert_eq!(level, 9);
    }
}
