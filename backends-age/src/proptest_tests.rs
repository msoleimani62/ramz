#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;
    use ramz_core::{PackOptions, ProgressReporter, Target};
    use std::io::Write;
    use tempfile::TempDir;

    struct NullProgress;
    impl ProgressReporter for NullProgress {
        fn set_total(&mut self, _total_bytes: u64) {}
        fn on_progress(&mut self, _processed_bytes: u64) {}
        fn finish(&mut self, _message: &str) {}
    }

    proptest! {
        #[test]
        fn test_age_encrypt_decrypt_roundtrip(
            content in prop::collection::vec(any::<u8>(), 0..65536),
            password in prop::string::string_regex("[a-zA-Z0-9!@#$%^&*]{8,64}").unwrap(),
            level in 1u8..=22
        ) {
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join("data.bin");
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(&content).unwrap();

            let target = Target::detect(&file).unwrap();
            let backend = AgeBackend::new();
            let archive = tmp.path().join("data.age.tar.zst");
            let opts = PackOptions {
                password: Some(password.clone()),
                compression_level: level,
                delete_source: false,
                output_dir: Some(tmp.path().to_path_buf()),
                force_overwrite: true,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            };

            let mut progress = NullProgress;
            backend.pack(&target, &archive, &opts, &mut progress).unwrap();

            let mut reader = std::fs::File::open(&archive).unwrap();
            let mut decrypted = Vec::new();
            backend.decrypt_to_writer(&mut reader, &mut decrypted, Some(&password)).unwrap();

            let mut tar = tar::Archive::new(&decrypted[..]);
            let extract_dir = tmp.path().join("extracted");
            std::fs::create_dir(&extract_dir).unwrap();
            tar.unpack(&extract_dir).unwrap();

            let extracted = extract_dir.join("data.bin");
            prop_assert!(extracted.exists());
            let extracted_content = std::fs::read(&extracted).unwrap();
            prop_assert_eq!(extracted_content, content);
        }

        #[test]
        fn test_age_wrong_password_fails(
            content in prop::collection::vec(any::<u8>(), 1..1024),
            correct_pw in prop::string::string_regex("[a-zA-Z0-9]{8,32}").unwrap(),
            wrong_pw in prop::string::string_regex("[a-zA-Z0-9]{8,32}").unwrap()
        ) {
            prop_assume!(correct_pw != wrong_pw);
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join("secret.bin");
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(&content).unwrap();

            let target = Target::detect(&file).unwrap();
            let backend = AgeBackend::new();
            let archive = tmp.path().join("secret.age.tar.zst");
            let opts = PackOptions {
                password: Some(correct_pw),
                compression_level: 3,
                delete_source: false,
                output_dir: Some(tmp.path().to_path_buf()),
                force_overwrite: true,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            };

            let mut progress = NullProgress;
            backend.pack(&target, &archive, &opts, &mut progress).unwrap();

            let mut reader = std::fs::File::open(&archive).unwrap();
            let mut decrypted = Vec::new();
            let result = backend.decrypt_to_writer(&mut reader, &mut decrypted, Some(&wrong_pw));
            prop_assert!(result.is_err());
        }
    }
}
