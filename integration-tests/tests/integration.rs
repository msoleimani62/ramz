use std::fs;
use std::io::Read;
use std::path::PathBuf;

use ramz_backend_7z::SevenZBackend;
use ramz_backends_age::{identity::Identity, AgeBackend};
use ramz_core::{Backend, PackOptions, ProgressReporter, Target};

// Null progress reporter for tests
// گزارش‌گر پیشرفت خالی برای تست‌ها
struct NullProgress;
impl ProgressReporter for NullProgress {
    fn set_total(&mut self, _total_bytes: u64) {}
    fn on_progress(&mut self, _processed_bytes: u64) {}
    fn finish(&mut self, _message: &str) {}
}

#[test]
fn test_age_backend_file_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("secret.txt");
    fs::write(&file, b"hello world from age").unwrap();
    let archive = tmp.path().join("secret.txt.age.tar.zst");

    let target = Target::detect(&file).unwrap();
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
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("test-password-123")).unwrap();

    let extract_dir = tmp.path().join("extracted");
    backend
        .extract(&archive, &extract_dir, Some("test-password-123"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("secret.txt")).unwrap();
    assert_eq!(extracted, b"hello world from age");
}

#[test]
fn test_age_backend_directory_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("project");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("main.rs"), b"fn main() {}").unwrap();
    let archive = tmp.path().join("project.age.tar.zst");

    let target = Target::detect(&dir).unwrap();
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
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("dir-password-456")).unwrap();
}

#[test]
fn test_age_backend_argon2id_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("argon2.txt");
    fs::write(&file, b"argon2id test data").unwrap();
    let archive = tmp.path().join("argon2.age.tar.zst");

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_argon2id();
    let opts = PackOptions {
        password: Some("argon2-password".to_string()),
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("argon2-password")).unwrap();

    let extract_dir = tmp.path().join("extracted_argon2");
    backend
        .extract(&archive, &extract_dir, Some("argon2-password"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("argon2.txt")).unwrap();
    assert_eq!(extracted, b"argon2id test data");
}

#[test]
fn test_age_backend_mlkem_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("mlkem.txt");
    fs::write(&file, b"ml-kem hybrid encryption test").unwrap();
    let archive = tmp.path().join("mlkem.age.tar.zst");

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_mlkem();
    let opts = PackOptions {
        password: Some("mlkem-password".to_string()),
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("mlkem-password")).unwrap();

    let extract_dir = tmp.path().join("extracted_mlkem");
    backend
        .extract(&archive, &extract_dir, Some("mlkem-password"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("mlkem.txt")).unwrap();
    assert_eq!(extracted, b"ml-kem hybrid encryption test");
}

#[test]
fn test_age_backend_recipient_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("recipient.txt");
    fs::write(&file, b"recipient-only post-quantum encryption").unwrap();
    let archive = tmp.path().join("recipient.age.tar.zst");

    let identity = Identity::generate();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");
    identity.save(&pub_path, &sec_path, None).unwrap();

    let mut pub_file = fs::File::open(&pub_path).unwrap();
    let mut pub_raw = Vec::new();
    pub_file.read_to_end(&mut pub_raw).unwrap();
    assert!(pub_raw.starts_with(b"RIM1PUB"));

    let mut pos = 7usize;
    let ek_len = u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let ek = pub_raw[pos..pos + ek_len].to_vec();

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_recipient(ek);
    let opts = PackOptions {
        password: None,
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    let loaded_identity = Identity::load_with_password(&pub_path, &sec_path, "").unwrap();
    backend
        .extract_to_dir(&archive, tmp.path(), None, Some(&loaded_identity))
        .unwrap();

    let extracted = fs::read(tmp.path().join("recipient.txt")).unwrap();
    assert_eq!(extracted, b"recipient-only post-quantum encryption");
}

#[test]
fn test_age_backend_recipient_verify_with_identity() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("recipient.txt");
    fs::write(&file, b"verify with identity").unwrap();
    let archive = tmp.path().join("recipient.age.tar.zst");

    let identity = Identity::generate();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");
    identity.save(&pub_path, &sec_path, None).unwrap();

    let mut pub_file = fs::File::open(&pub_path).unwrap();
    let mut pub_raw = Vec::new();
    pub_file.read_to_end(&mut pub_raw).unwrap();
    let mut pos = 7usize;
    let ek_len = u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let ek = pub_raw[pos..pos + ek_len].to_vec();

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_recipient(ek);
    let opts = PackOptions {
        password: None,
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();

    let loaded_identity = Identity::load_with_password(&pub_path, &sec_path, "").unwrap();
    backend
        .verify_with_identity(&archive, &loaded_identity)
        .unwrap();
}

#[test]
fn test_age_backend_recipient_without_identity_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("recipient.txt");
    fs::write(&file, b"should fail without identity").unwrap();
    let archive = tmp.path().join("recipient.age.tar.zst");

    let identity = Identity::generate();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");
    identity.save(&pub_path, &sec_path, None).unwrap();

    let mut pub_file = fs::File::open(&pub_path).unwrap();
    let mut pub_raw = Vec::new();
    pub_file.read_to_end(&mut pub_raw).unwrap();
    let mut pos = 7usize;
    let ek_len = u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let ek = pub_raw[pos..pos + ek_len].to_vec();

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_recipient(ek);
    let opts = PackOptions {
        password: None,
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();

    let result = backend.verify(&archive, None);
    assert!(result.is_err());
}

#[test]
fn test_age_backend_recipient_with_password_protected_identity() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("recipient.txt");
    fs::write(&file, b"password protected identity").unwrap();
    let archive = tmp.path().join("recipient.age.tar.zst");

    let identity = Identity::generate();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");
    identity
        .save(&pub_path, &sec_path, Some("identity-password"))
        .unwrap();

    let mut pub_file = fs::File::open(&pub_path).unwrap();
    let mut pub_raw = Vec::new();
    pub_file.read_to_end(&mut pub_raw).unwrap();
    let mut pos = 7usize;
    let ek_len = u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let ek = pub_raw[pos..pos + ek_len].to_vec();

    let target = Target::detect(&file).unwrap();
    let backend = AgeBackend::new_with_recipient(ek);
    let opts = PackOptions {
        password: None,
        compression_level: 3,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();

    let loaded_identity =
        Identity::load_with_password(&pub_path, &sec_path, "identity-password").unwrap();
    backend
        .verify_with_identity(&archive, &loaded_identity)
        .unwrap();

    backend
        .extract_to_dir(&archive, tmp.path(), None, Some(&loaded_identity))
        .unwrap();
    let extracted = fs::read(tmp.path().join("recipient.txt")).unwrap();
    assert_eq!(extracted, b"password protected identity");
}

#[test]
fn test_identity_generate_save_load_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");

    let identity = Identity::generate();
    identity.save(&pub_path, &sec_path, None).unwrap();

    assert!(pub_path.exists());
    assert!(sec_path.exists());

    let loaded = Identity::load_with_password(&pub_path, &sec_path, "").unwrap();
    assert_eq!(loaded.encapsulation_key, identity.encapsulation_key);
    assert_eq!(
        loaded.decapsulation_key.as_slice(),
        identity.decapsulation_key.as_slice()
    );
}

#[test]
fn test_identity_password_protected_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");

    let identity = Identity::generate();
    identity
        .save(&pub_path, &sec_path, Some("my-secret-password"))
        .unwrap();

    let loaded = Identity::load_with_password(&pub_path, &sec_path, "my-secret-password").unwrap();
    assert_eq!(loaded.encapsulation_key, identity.encapsulation_key);
    assert_eq!(
        loaded.decapsulation_key.as_slice(),
        identity.decapsulation_key.as_slice()
    );
}

#[test]
fn test_identity_wrong_password_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let pub_path = tmp.path().join("identity.pub");
    let sec_path = tmp.path().join("identity");

    let identity = Identity::generate();
    identity
        .save(&pub_path, &sec_path, Some("correct-password"))
        .unwrap();

    let result = Identity::load_with_password(&pub_path, &sec_path, "wrong-password");
    assert!(result.is_err());
}

#[test]
fn test_sevenz_backend_name_and_extension() {
    let backend = SevenZBackend;
    assert_eq!(backend.name(), "7z");
    assert_eq!(backend.extension(), "7z");
    assert!(backend.requires_external_binary());
}

// این تست چرخه‌ی کامل واقعی بک‌اند 7z (pack → verify → extract) رو تست
// می‌کنه - نه فقط متادیتا. قبلاً این نوع تست وجود داشت ولی موقع بازنویسی
// این فایل گم شده بود؛ بدون این، کل مسیر رمزنگاری/فشرده‌سازی 7z عملاً
// پوشش تستی نداشت با این‌که خودِ CI باینری 7z رو نصب می‌کنه
// this test exercises the real, full 7z backend cycle (pack → verify →
// extract), not just metadata. this kind of test existed before but was
// lost when this file got rewritten; without it, the entire 7z
// encryption/compression path had no real test coverage even though CI
// installs the 7z binary specifically for this
#[test]
fn test_sevenz_backend_file_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("document.txt");
    fs::write(&file, b"7z backend roundtrip test content").unwrap();
    let archive = tmp.path().join("document.7z");

    let target = Target::detect(&file).unwrap();
    let backend = SevenZBackend;
    let opts = PackOptions {
        password: Some("7z-password-789".to_string()),
        compression_level: 5,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();
    assert!(archive.exists());

    backend.verify(&archive, Some("7z-password-789")).unwrap();

    let extract_dir = tmp.path().join("extracted_7z");
    backend
        .extract(&archive, &extract_dir, Some("7z-password-789"))
        .unwrap();
    let extracted = fs::read(extract_dir.join("document.txt")).unwrap();
    assert_eq!(extracted, b"7z backend roundtrip test content");
}

#[test]
fn test_sevenz_backend_wrong_password_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("secret.bin");
    fs::write(&file, b"\x00\x01\x02\x03").unwrap();
    let archive = tmp.path().join("secret.7z");

    let target = Target::detect(&file).unwrap();
    let backend = SevenZBackend;
    let opts = PackOptions {
        password: Some("correct-password".to_string()),
        compression_level: 5,
        delete_source: false,
        output_dir: Some(tmp.path().to_path_buf()),
        force_overwrite: true,
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        secure_delete: false,
    };

    let mut progress = NullProgress;
    backend
        .pack(&target, &archive, &opts, &mut progress)
        .unwrap();

    let result = backend.verify(&archive, Some("wrong-password"));
    assert!(result.is_err());
}

#[test]
fn test_resume_state_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let archive = tmp.path().join("test.age.tar.zst");
    fs::File::create(&archive).unwrap();

    let state = ramz_core::resume::ResumeState {
        source_path: PathBuf::from("/source"),
        archive_path: archive.clone(),
        backend_name: "age".to_string(),
        total_bytes: 1000,
        processed_bytes: 500,
        checksum: "abc123".to_string(),
        password_hint: None,
        created_at: "now".to_string(),
    };

    ramz_core::resume::save_resume_state(&state, &archive).unwrap();
    assert!(ramz_core::resume::is_resumable(&archive));

    let loaded = ramz_core::resume::load_resume_state(&archive)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.total_bytes, 1000);
    assert_eq!(loaded.processed_bytes, 500);

    ramz_core::resume::remove_resume_state(&archive).unwrap();
    assert!(!ramz_core::resume::is_resumable(&archive));
}

#[test]
fn test_verify_source_unchanged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    let checksum = ramz_core::resume::compute_file_checksum(&file).unwrap();
    let state = ramz_core::resume::ResumeState {
        source_path: file.clone(),
        archive_path: tmp.path().join("archive.age.tar.zst"),
        backend_name: "age".to_string(),
        total_bytes: 5,
        processed_bytes: 5,
        checksum,
        password_hint: None,
        created_at: "now".to_string(),
    };

    assert!(ramz_core::resume::verify_source_unchanged(&state).unwrap());

    fs::write(&file, b"changed").unwrap();
    assert!(!ramz_core::resume::verify_source_unchanged(&state).unwrap());
}

#[test]
fn test_dry_run_estimate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    fs::write(&file, b"hello world this is a test file").unwrap();

    let target = Target::detect(&file).unwrap();
    let opts = PackOptions::default();
    let report = ramz_core::dry_run::estimate_archive_size(&target, &opts, "age").unwrap();

    assert_eq!(report.source_size, 31);
    assert!(report.estimated_archive_size > 0);
    assert_eq!(report.backend_name, "age");
    assert!(!report.password_protected);
}

#[test]
fn test_secure_delete_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("secret.txt");
    fs::write(&file, b"top secret data").unwrap();

    ramz_core::secure_delete::secure_delete_file(&file).unwrap();
    assert!(!file.exists());
}

#[test]
fn test_delete_path_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    ramz_core::secure_delete::delete_path(&file, false).unwrap();
    assert!(!file.exists());
}

#[test]
fn test_delete_path_directory() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("subdir");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("file.txt"), b"hello").unwrap();

    ramz_core::secure_delete::delete_path(&dir, false).unwrap();
    assert!(!dir.exists());
}
