use std::fs;
use std::io::Write;
use std::path::Path;

use ramz_core::{Backend, PackOptions, ProgressReporter, Target};
use ramz_backends_age::AgeBackend;
use ramz_backends_7z::SevenZBackend;
use tempfile::TempDir;

struct TestProgress;
impl ProgressReporter for TestProgress {
    fn set_total(&mut self, _total_bytes: u64) {}
    fn on_progress(&mut self, _processed_bytes: u64) {}
    fn finish(&mut self, _message: &str) {}
}

fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(content).unwrap();
    path
}

fn create_test_dir(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn test_age_backend_file_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "secret.txt", b"hello world from age");
    let archive = tmp.path().join("secret.txt.age.tar.zst");
    let extract_dir = tmp.path().join("extracted");

    let target = Target::detect(&source).unwrap();
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
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend
        .verify(&archive, Some("test-password-123"))
        .unwrap();

    fs::create_dir(&extract_dir).unwrap();
    let mut reader = fs::File::open(&archive).unwrap();
    let mut decrypted = Vec::new();
    backend
        .decrypt_to_writer(&mut reader, &mut decrypted, Some("test-password-123"))
        .unwrap();

    let mut tar = tar::Archive::new(&decrypted[..]);
    tar.unpack(&extract_dir).unwrap();

    let extracted_file = extract_dir.join("secret.txt");
    assert!(extracted_file.exists());
    let content = fs::read_to_string(&extracted_file).unwrap();
    assert_eq!(content, "hello world from age");
}

#[test]
fn test_age_backend_directory_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source_dir = create_test_dir(tmp.path(), "project");
    create_test_file(&source_dir, "main.rs", b"fn main() {}");
    create_test_file(&source_dir, "Cargo.toml", b"[package]\nname = \"test\"");
    let subdir = create_test_dir(&source_dir, "src");
    create_test_file(&subdir, "lib.rs", b"pub fn add(a: i32, b: i32) -> i32 { a + b }");

    let archive = tmp.path().join("project.age.tar.zst");
    let extract_dir = tmp.path().join("extracted");

    let target = Target::detect(&source_dir).unwrap();
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
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend
        .verify(&archive, Some("dir-password-456"))
        .unwrap();

    fs::create_dir(&extract_dir).unwrap();
    let mut reader = fs::File::open(&archive).unwrap();
    let mut decrypted = Vec::new();
    backend
        .decrypt_to_writer(&mut reader, &mut decrypted, Some("dir-password-456"))
        .unwrap();

    let mut tar = tar::Archive::new(&decrypted[..]);
    tar.unpack(&extract_dir).unwrap();

    let extracted = extract_dir.join("project");
    assert!(extracted.join("main.rs").exists());
    assert!(extracted.join("Cargo.toml").exists());
    assert!(extracted.join("src/lib.rs").exists());

    let lib_content = fs::read_to_string(extracted.join("src/lib.rs")).unwrap();
    assert!(lib_content.contains("add"));
}

#[test]
fn test_7z_backend_file_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "document.pdf", b"%PDF-1.4 fake pdf content");
    let archive = tmp.path().join("document.7z");
    let extract_dir = tmp.path().join("extracted");

    let target = Target::detect(&source).unwrap();
    let backend = SevenZBackend::new();
    let opts = PackOptions {
        password: Some("7z-password-789".to_string()),
        compression_level: 5,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend
        .verify(&archive, Some("7z-password-789"))
        .unwrap();

    fs::create_dir(&extract_dir).unwrap();
    backend
        .extract(&archive, &extract_dir, Some("7z-password-789"))
        .unwrap();

    let extracted = extract_dir.join("document.pdf");
    assert!(extracted.exists());
    let content = fs::read(&extracted).unwrap();
    assert_eq!(content, b"%PDF-1.4 fake pdf content");
}

#[test]
fn test_7z_backend_directory_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source_dir = create_test_dir(tmp.path(), "website");
    create_test_file(&source_dir, "index.html", b"<html><body>Hello</body></html>");
    create_test_file(&source_dir, "style.css", b"body { color: red; }");
    let js_dir = create_test_dir(&source_dir, "js");
    create_test_file(&js_dir, "app.js", b"console.log('hello');");

    let archive = tmp.path().join("website.7z");
    let extract_dir = tmp.path().join("extracted");

    let target = Target::detect(&source_dir).unwrap();
    let backend = SevenZBackend::new();
    let opts = PackOptions {
        password: Some("web-password-000".to_string()),
        compression_level: 7,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend
        .verify(&archive, Some("web-password-000"))
        .unwrap();

    fs::create_dir(&extract_dir).unwrap();
    backend
        .extract(&archive, &extract_dir, Some("web-password-000"))
        .unwrap();

    let extracted = extract_dir.join("website");
    assert!(extracted.join("index.html").exists());
    assert!(extracted.join("style.css").exists());
    assert!(extracted.join("js/app.js").exists());
}

#[test]
fn test_age_backend_wrong_password_fails() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "secret.txt", b"top secret");
    let archive = tmp.path().join("secret.age.tar.zst");

    let target = Target::detect(&source).unwrap();
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
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();

    let result = backend.verify(&archive, Some("wrong-password"));
    assert!(result.is_err());
}

#[test]
fn test_7z_backend_wrong_password_fails() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "data.bin", b"\x00\x01\x02\x03");
    let archive = tmp.path().join("data.7z");

    let target = Target::detect(&source).unwrap();
    let backend = SevenZBackend::new();
    let opts = PackOptions {
        password: Some("correct-password".to_string()),
        compression_level: 5,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();

    let result = backend.verify(&archive, Some("wrong-password"));
    assert!(result.is_err());
}

#[test]
fn test_age_backend_large_file() {
    let tmp = TempDir::new().unwrap();
    let large_content = vec![0xABu8; 1024 * 1024]; // 1MB
    let source = create_test_file(tmp.path(), "large.bin", &large_content);
    let archive = tmp.path().join("large.age.tar.zst");
    let extract_dir = tmp.path().join("extracted");

    let target = Target::detect(&source).unwrap();
    let backend = AgeBackend::new();
    let opts = PackOptions {
        password: Some("large-file-pw".to_string()),
        compression_level: 6,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();

    fs::create_dir(&extract_dir).unwrap();
    let mut reader = fs::File::open(&archive).unwrap();
    let mut decrypted = Vec::new();
    backend
        .decrypt_to_writer(&mut reader, &mut decrypted, Some("large-file-pw"))
        .unwrap();

    let mut tar = tar::Archive::new(&decrypted[..]);
    tar.unpack(&extract_dir).unwrap();

    let extracted = extract_dir.join("large.bin");
    let extracted_content = fs::read(&extracted).unwrap();
    assert_eq!(extracted_content, large_content);
}

#[test]
fn test_7z_backend_empty_directory_fails() {
    let tmp = TempDir::new().unwrap();
    let empty_dir = tmp.path().join("empty");
    fs::create_dir(&empty_dir).unwrap();

    let result = Target::detect(&empty_dir);
    assert!(result.is_err());
}

#[test]
fn test_both_backends_with_special_characters() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "special-!@#$%^&*().txt", b"special chars");
    let archive_age = tmp.path().join("special.age.tar.zst");
    let archive_7z = tmp.path().join("special.7z");

    let target = Target::detect(&source).unwrap();

    // Age backend
    let age = AgeBackend::new();
    let opts = PackOptions {
        password: Some("pw".to_string()),
        compression_level: 1,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };
    let mut progress = TestProgress;
    age.pack(&target, &archive_age, &opts, &mut progress).unwrap();
    assert!(archive_age.exists());

    // 7z backend
    let sevenz = SevenZBackend::new();
    let mut progress = TestProgress;
    sevenz.pack(&target, &archive_7z, &opts, &mut progress).unwrap();
    assert!(archive_7z.exists());
}

#[test]
fn test_age_backend_argon2id_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "argon2.txt", b"argon2id integration test");
    let archive = tmp.path().join("argon2.age.tar.zst");
    let extract_dir = tmp.path().join("extracted_argon2");

    let target = Target::detect(&source).unwrap();
    let backend = AgeBackend::new_with_argon2id();
    let opts = PackOptions {
        password: Some("argon2-pw".to_string()),
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 32768,
        argon2_iterations: 2,
        argon2_parallelism: 2,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("argon2-pw")).unwrap();

    fs::create_dir(&extract_dir).unwrap();
    backend
        .extract_to_dir(&archive, &extract_dir, Some("argon2-pw"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("argon2.txt")).unwrap();
    assert_eq!(extracted, b"argon2id integration test");
}

#[test]
fn test_age_backend_mlkem_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let source = create_test_file(tmp.path(), "mlkem.txt", b"ml-kem integration test");
    let archive = tmp.path().join("mlkem.age.tar.zst");
    let extract_dir = tmp.path().join("extracted_mlkem");

    let target = Target::detect(&source).unwrap();
    let backend = AgeBackend::new_with_mlkem();
    let opts = PackOptions {
        password: Some("mlkem-pw".to_string()),
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let mut progress = TestProgress;
    backend.pack(&target, &archive, &opts, &mut progress).unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("mlkem-pw")).unwrap();

    fs::create_dir(&extract_dir).unwrap();
    backend
        .extract_to_dir(&archive, &extract_dir, Some("mlkem-pw"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("mlkem.txt")).unwrap();
    assert_eq!(extracted, b"ml-kem integration test");
}
