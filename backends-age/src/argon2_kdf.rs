use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use rand::rngs::OsRng;
use rand::RngCore;

use ramz_core::{RamzError, Result};
use zeroize::Zeroizing;

// Generate a random 16-byte salt using OS RNG
// تولید salt تصادفی 16 بایتی با استفاده از RNG سیستم‌عامل
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

// Derive a 32-byte key from password using Argon2id
// استخراج کلید 32 بایتی از پسورد با استفاده از Argon2id
pub fn derive_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| RamzError::Backend(format!("argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| RamzError::Backend(format!("salt encode: {}", e)))?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| RamzError::Backend(format!("argon2 hash: {}", e)))?;

    let key_bytes = hash
        .hash
        .ok_or_else(|| RamzError::Backend("argon2 produced no hash".into()))?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    key.copy_from_slice(key_bytes.as_ref());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = generate_salt();
        let k1 = derive_key("password", &salt, 65536, 3, 4).unwrap();
        let k2 = derive_key("password", &salt, 65536, 3, 4).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = generate_salt();
        let k1 = derive_key("password1", &salt, 65536, 3, 4).unwrap();
        let k2 = derive_key("password2", &salt, 65536, 3, 4).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_derive_key_different_salts() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        let k1 = derive_key("password", &s1, 65536, 3, 4).unwrap();
        let k2 = derive_key("password", &s2, 65536, 3, 4).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }
}
