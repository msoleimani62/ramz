// Property-based tests using proptest
// تست‌های مبتنی بر ویژگی با استفاده از proptest
#[cfg(test)]
mod proptest {
    use proptest::prelude::*;
    use std::io::Write;
    use tempfile::TempDir;

    use crate::{pack_to_tar, unpack_from_tar, Target};

    proptest! {
        #[test]
        fn test_roundtrip_any_bytes(data: Vec<u8>) {
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join("data.bin");
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(&data).unwrap();

            let target = Target::detect(&file).unwrap();
            let mut buf = Vec::new();
            pack_to_tar(&target, &mut buf).unwrap();

            let extract_dir = tmp.path().join("extracted");
            std::fs::create_dir(&extract_dir).unwrap();
            unpack_from_tar(&buf[..], &extract_dir).unwrap();

            let extracted = std::fs::read(extract_dir.join("data.bin")).unwrap();
            prop_assert_eq!(data, extracted);
        }
    }
}
