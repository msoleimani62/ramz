// Argon2id key derivation function for age backend
// Replaces the default scrypt-based KDF with memory-hard Argon2id
// Argon2id KDF برای بک‌اند age — جایگزین scrypt پیش‌فرض با Argon2id حافظه‌سنگین

use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, Params, PasswordHasher,
};
use zeroize::Zeroizing;

const ARGON2_OUTPUT_LEN: usize = 32;

/// Derive a 256-bit key from a password and salt using Argon2id with configurable params.
/// مشتق کردن کلید ۲۵۶ بیتی از پسورد و salt با پارامترهای قابل‌تنظیم Argon2id
pub fn derive_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>, String> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(ARGON2_OUTPUT_LEN))
        .map_err(|e| format!("argon2 params error: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt_str = SaltString::encode_b64(salt).map_err(|e| format!("salt encode error: {}", e))?;

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| format!("argon2 hash error: {}", e))?;

    let hash = password_hash.hash.ok_or("missing hash")?;
    let mut key = [0u8; ARGON2_OUTPUT_LEN];
    key.copy_from_slice(&hash.as_bytes()[..ARGON2_OUTPUT_LEN]);
    Ok(Zeroizing::new(key))
}

/// Generate a random 16-byte salt.
/// تولید salt تصادفی ۱۶ بایتی
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = "test-password";
        let salt = b"fixed-salt-12345";
        let key1 = derive_key(password, salt, 65536, 3, 4).unwrap();
        let key2 = derive_key(password, salt, 65536, 3, 4).unwrap();
        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = b"same-salt-123456";
        let key1 = derive_key("password1", salt, 65536, 3, 4).unwrap();
        let key2 = derive_key("password2", salt, 65536, 3, 4).unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = "same-password";
        let key1 = derive_key(password, b"salt1-abc", 65536, 3, 4).unwrap();
        let key2 = derive_key(password, b"salt2-abc", 65536, 3, 4).unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_generate_salt_random() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), 16);
    }

    #[test]
    fn test_different_params_different_keys() {
        let password = "same-password";
        let salt = b"same-salt-123456";
        let key1 = derive_key(password, salt, 65536, 3, 4).unwrap();
        let key2 = derive_key(password, salt, 32768, 3, 4).unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }
}
