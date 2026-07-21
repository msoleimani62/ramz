use std::path::Path;

/// List of file extensions that are already compressed and should be stored without re-compression.
pub const ALREADY_COMPRESSED: &[&str] = &[
    // Images
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "ico", "heic", "avif", // Video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg", // Audio
    "mp3", "aac", "ogg", "wma", "flac", "m4a", "wav", "opus", // Archives
    "zip", "gz", "bz2", "xz", "lz4", "zst", "7z", "rar", "tar", "tgz", "tbz",
    // Documents
    "pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", // Executables
    "exe", "dll", "so", "dylib", "deb", "rpm", "msi", "apk", "ipa", // Fonts
    "woff", "woff2", "eot", "ttf", "otf", // Other
    "br", "lzma", "z", "cab",
];

pub fn is_already_compressed(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext_lower = ext.to_lowercase();
            ALREADY_COMPRESSED.contains(&ext_lower.as_str())
        })
        .unwrap_or(false)
}

pub fn should_compress(path: &Path) -> bool {
    !is_already_compressed(path)
}

pub fn effective_compression_level(path: &Path, requested_level: u8) -> u8 {
    if is_already_compressed(path) {
        0 // Store without compression
    } else {
        requested_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jpg_is_compressed() {
        assert!(is_already_compressed(Path::new("photo.jpg")));
        assert!(is_already_compressed(Path::new("photo.JPG")));
    }

    #[test]
    fn test_txt_is_not_compressed() {
        assert!(!is_already_compressed(Path::new("document.txt")));
    }

    #[test]
    fn test_mp4_is_compressed() {
        assert!(is_already_compressed(Path::new("video.mp4")));
    }

    #[test]
    fn test_pdf_is_compressed() {
        assert!(is_already_compressed(Path::new("doc.pdf")));
    }

    #[test]
    fn test_no_extension_not_compressed() {
        assert!(!is_already_compressed(Path::new("Makefile")));
    }

    #[test]
    fn test_effective_level_for_compressed() {
        assert_eq!(effective_compression_level(Path::new("a.jpg"), 9), 0);
    }

    #[test]
    fn test_effective_level_for_uncompressed() {
        assert_eq!(effective_compression_level(Path::new("a.txt"), 9), 9);
    }
}
