#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Write;
    use tempfile::TempDir;

    proptest! {
        #[test]
        fn test_dir_size_matches_actual(
            files in prop::collection::vec(
                (prop::string::string_regex("[a-zA-Z0-9_]+").unwrap(), prop::collection::vec(any::<u8>(), 0..1024)),
                0..10
            )
        ) {
            let tmp = TempDir::new().unwrap();
            let mut total = 0u64;
            for (name, content) in &files {
                let path = tmp.path().join(name);
                let mut f = std::fs::File::create(&path).unwrap();
                f.write_all(content).unwrap();
                total += content.len() as u64;
            }
            prop_assert_eq!(dir_size(tmp.path()).unwrap(), total);
        }

        #[test]
        fn test_safe_output_dir_never_empty(
            path in "(/[a-zA-Z0-9_]+)+"
        ) {
            let p = std::path::Path::new(&path);
            let result = safe_output_dir(p, None);
            prop_assert!(!result.as_os_str().is_empty());
        }

        #[test]
        fn test_read_and_confirm_password_properties(
            pw in prop::string::string_regex("[a-zA-Z0-9!@#$%^&*]{1,64}").unwrap()
        ) {
            let result = read_and_confirm_password(
                || Ok(pw.clone()),
                || Ok(pw.clone()),
            );
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap(), pw);
        }

        #[test]
        fn test_password_mismatch_always_fails(
            pw1 in prop::string::string_regex("[a-zA-Z0-9]{1,32}").unwrap(),
            pw2 in prop::string::string_regex("[a-zA-Z0-9]{1,32}").unwrap()
        ) {
            prop_assume!(pw1 != pw2);
            let result = read_and_confirm_password(
                || Ok(pw1.clone()),
                || Ok(pw2.clone()),
            );
            prop_assert!(matches!(result, Err(RamzError::PasswordMismatch)));
        }

        #[test]
        fn test_empty_password_always_fails(
            _empty in Just(())
        ) {
            let result = read_and_confirm_password(
                || Ok("".to_string()),
                || Ok("".to_string()),
            );
            prop_assert!(matches!(result, Err(RamzError::EmptyPassword)));
        }

        #[test]
        fn test_pack_to_tar_roundtrip(
            content in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join("test.bin");
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(&content).unwrap();

            let target = Target::detect(&file).unwrap();
            let mut buf = Vec::new();
            pack_to_tar(&target, &mut buf).unwrap();

            let extract_dir = tmp.path().join("extracted");
            std::fs::create_dir(&extract_dir).unwrap();
            unpack_from_tar(&buf[..], &extract_dir).unwrap();

            let extracted = extract_dir.join("test.bin");
            prop_assert!(extracted.exists());
            let extracted_content = std::fs::read(&extracted).unwrap();
            prop_assert_eq!(extracted_content, content);
        }
    }
}
