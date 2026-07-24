// Property-based tests for age backend
// تست‌های مبتنی بر ویژگی برای backend age
#[cfg(test)]
mod proptest {
    use proptest::prelude::*;
    use std::io::Write;
    use tempfile::TempDir;

    use ramz_core::{PackOptions, ProgressReporter, Target};

    use crate::AgeBackend;

    struct NullProgress;
    impl ProgressReporter for NullProgress {
        fn set_total(&mut self, _total_bytes: u64) {}
        fn on_progress(&mut self, _processed_bytes: u64) {}
        fn finish(&mut self, _message: &str) {}
    }

    proptest! {
        #[test]
        fn test_roundtrip_any_data(data: Vec<u8>) {
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join("data.bin");
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(&data).unwrap();

            let target = Target::detect(&file).unwrap();
            let backend = AgeBackend::new();
            let archive = tmp.path().join("data.bin.age.tar.zst");
            let opts = PackOptions {
                password: Some("test-password".to_string()),
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
            backend.pack(&target, &archive, &opts, &mut progress).unwrap();
            backend.verify(&archive, Some("test-password")).unwrap();

            let extract_dir = tmp.path().join("extracted");
            backend.extract(&archive, &extract_dir, Some("test-password")).unwrap();
            let extracted = std::fs::read(extract_dir.join("data.bin")).unwrap();
            prop_assert_eq!(data, extracted);
        }
    }
}
