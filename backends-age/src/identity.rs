use std::fs;
use std::io::Read;
use std::path::Path;

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use zeroize::Zeroizing;

use ramz_core::{RamzError, Result};

use crate::argon2_kdf;
use crate::mlkem_hybrid;

// بایت‌های جادویی فرمت فایل identity
// magic bytes identifying the identity file format
const RIM1_MAGIC: &[u8; 7] = b"RIM1SEC";
const RIM1PUB_MAGIC: &[u8; 7] = b"RIM1PUB";

// فلگ‌های حالت محافظت کلید سری - اولین بایت بعد از magic
// protection-mode flags for the secret key - first byte after the magic
const PROTECTION_NONE: u8 = 0;
const PROTECTION_PASSWORD: u8 = 1;

// identity ML-KEM برای رمزنگاری مبتنی بر گیرنده (recipient-based)
// an ML-KEM identity for recipient-based encryption
pub struct Identity {
    pub encapsulation_key: Vec<u8>,
    pub decapsulation_key: Zeroizing<Vec<u8>>,
}

impl Identity {
    // تولید یک جفت‌کلید identity ML-KEM-768 جدید
    // generate a new ML-KEM-768 identity keypair
    pub fn generate() -> Self {
        let kp = mlkem_hybrid::generate_keypair();
        Identity {
            encapsulation_key: kp.public_key,
            decapsulation_key: kp.secret_key,
        }
    }

    // ذخیره identity روی دیسک (عمومی + سری با پسورد اختیاری)
    // save identity to disk (public key + secret key with an optional password)
    pub fn save(&self, pub_path: &Path, sec_path: &Path, password: Option<&str>) -> Result<()> {
        // ذخیره کلید عمومی (encapsulation key) - این فایل رو می‌شه آزادانه به اشتراک گذاشت
        // save the public key (encapsulation key) - this file can be shared freely
        let mut pub_data = RIM1PUB_MAGIC.to_vec();
        pub_data.extend_from_slice(&(self.encapsulation_key.len() as u32).to_le_bytes());
        pub_data.extend_from_slice(&self.encapsulation_key);
        fs::write(pub_path, &pub_data)?;

        let mut sec_data = RIM1_MAGIC.to_vec();

        match password {
            Some(pw) => {
                // محافظت‌شده با پسورد: کلید سری با ChaCha20-Poly1305 و کلید
                // مشتق‌شده از Argon2id رمزنگاری می‌شه - این یه رمزنگاری واقعیه
                // چون کلید رمزگشایی هیچ‌جای فایل ذخیره نمی‌شه، فقط از پسورد
                // مشتق می‌شه
                // password-protected: the secret key is encrypted with
                // ChaCha20-Poly1305 using an Argon2id-derived key - this is real
                // encryption, since the decryption key is never stored in the
                // file, only derived from the password
                sec_data.push(PROTECTION_PASSWORD);

                let salt = argon2_kdf::generate_salt();
                let argon2_key = argon2_kdf::derive_key(pw, &salt, 65536, 3, 4)
                    .map_err(|e| RamzError::Backend(format!("identity key derivation: {}", e)))?;

                let nonce = generate_nonce();
                let cipher = ChaCha20Poly1305::new(Key::from_slice(argon2_key.as_slice()));
                let encrypted = cipher
                    .encrypt(Nonce::from_slice(&nonce), self.decapsulation_key.as_slice())
                    .map_err(|e| RamzError::Backend(format!("identity encrypt: {}", e)))?;

                sec_data.extend_from_slice(&salt);
                sec_data.extend_from_slice(&nonce);
                sec_data.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
                sec_data.extend_from_slice(&encrypted);
            }
            None => {
                // بدون پسورد: کلید سری مستقیم و بدون رمزنگاری ذخیره می‌شه.
                // قبلاً اینجا با یه کلید تصادفی که کنار خودش ذخیره می‌شد
                // "رمزنگاری" می‌شد - این هیچ محافظتی فراتر از plaintext نمی‌داد،
                // فقط توهم امنیت ایجاد می‌کرد و پیچیدگی بی‌فایده اضافه می‌کرد.
                // تنها محافظت واقعی توی این حالت، permission سطح فایل‌سیستم
                // (chmod 600 پایین همین تابع) هست - دقیقاً مثل کاری که
                // ssh-keygen بدون passphrase می‌کنه.
                //
                // no password: the secret key is stored directly, unencrypted.
                // this used to be "encrypted" with a random key stored right
                // next to it in the same file - that provided zero protection
                // beyond plaintext, only the illusion of security, plus
                // pointless complexity. the only real protection in this mode
                // is the filesystem permission (chmod 600, below) - exactly
                // what ssh-keygen does for a passphrase-less key.
                sec_data.push(PROTECTION_NONE);
                sec_data.extend_from_slice(&(self.decapsulation_key.len() as u32).to_le_bytes());
                sec_data.extend_from_slice(self.decapsulation_key.as_slice());
            }
        }

        fs::write(sec_path, &sec_data)?;

        // محدودکردن دسترسی فایل کلید سری فقط به مالکش
        // restrict the secret key file to owner-only access
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(sec_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(sec_path, perms)?;
        }

        Ok(())
    }

    // بارگذاری identity از دیسک؛ اگه با پسورد محافظت شده باشه، رمزگشایی می‌کنه.
    // پسورد خالی ("") یعنی «سعی کن بدون پسورد باز کنی» - اگه فایل واقعاً
    // بدون پسورد ذخیره شده باشه کار می‌کنه، وگرنه خطای رمزگشایی می‌ده.
    // load identity from disk; decrypts the secret key if it was
    // password-protected. an empty password ("") means "try without a
    // password" - this succeeds only if the file was actually stored without
    // one, otherwise decryption fails.
    pub fn load_with_password(pub_path: &Path, sec_path: &Path, password: &str) -> Result<Self> {
        let mut pub_file = fs::File::open(pub_path)?;
        let mut pub_raw = Vec::new();
        pub_file.read_to_end(&mut pub_raw)?;

        if !pub_raw.starts_with(RIM1PUB_MAGIC) {
            return Err(RamzError::Backend("invalid public identity file".into()));
        }

        let mut pos = RIM1PUB_MAGIC.len();
        let ek_len = u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ek = pub_raw[pos..pos + ek_len].to_vec();

        let mut sec_file = fs::File::open(sec_path)?;
        let mut sec_raw = Vec::new();
        sec_file.read_to_end(&mut sec_raw)?;

        if !sec_raw.starts_with(RIM1_MAGIC) {
            return Err(RamzError::Backend("invalid secret identity file".into()));
        }

        let mut pos = RIM1_MAGIC.len();
        let protection_flag = *sec_raw
            .get(pos)
            .ok_or_else(|| RamzError::Backend("truncated identity file".into()))?;
        pos += 1;

        let dk = match protection_flag {
            PROTECTION_NONE => {
                // کلید مستقیم و بدون رمزنگاری ذخیره شده؛ فقط می‌خونیمش
                // the key was stored directly, unencrypted; just read it
                let dk_len = u32::from_le_bytes(sec_raw[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                sec_raw[pos..pos + dk_len].to_vec()
            }
            PROTECTION_PASSWORD => {
                // محافظت‌شده با پسورد: کلید از پسورد + salt مشتق و رمزگشایی می‌شه
                // password-protected: derive the key from password + salt and decrypt
                let salt = &sec_raw[pos..pos + 16];
                pos += 16;
                let nonce: [u8; 12] = sec_raw[pos..pos + 12].try_into().unwrap();
                pos += 12;
                let enc_len =
                    u32::from_le_bytes(sec_raw[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                let encrypted = &sec_raw[pos..pos + enc_len];

                let argon2_key = argon2_kdf::derive_key(password, salt, 65536, 3, 4)
                    .map_err(|e| RamzError::Backend(format!("identity key derivation: {}", e)))?;

                let cipher = ChaCha20Poly1305::new(Key::from_slice(argon2_key.as_slice()));
                cipher
                    .decrypt(Nonce::from_slice(&nonce), encrypted)
                    .map_err(|_| RamzError::Backend("wrong identity password".into()))?
            }
            _ => {
                return Err(RamzError::Backend(
                    "unknown identity protection mode".into(),
                ))
            }
        };

        Ok(Identity {
            encapsulation_key: ek,
            decapsulation_key: Zeroizing::new(dk),
        })
    }
}

fn generate_nonce() -> [u8; 12] {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_identity_generate_save_load_no_password() {
        let tmp = TempDir::new().unwrap();
        let pub_path = tmp.path().join("identity.pub");
        let sec_path = tmp.path().join("identity");

        let identity = Identity::generate();
        identity.save(&pub_path, &sec_path, None).unwrap();

        let loaded = Identity::load_with_password(&pub_path, &sec_path, "").unwrap();
        assert_eq!(loaded.encapsulation_key, identity.encapsulation_key);
        assert_eq!(
            loaded.decapsulation_key.as_slice(),
            identity.decapsulation_key.as_slice()
        );
    }

    #[test]
    fn test_identity_generate_save_load_with_password() {
        let tmp = TempDir::new().unwrap();
        let pub_path = tmp.path().join("identity.pub");
        let sec_path = tmp.path().join("identity");

        let identity = Identity::generate();
        identity
            .save(&pub_path, &sec_path, Some("mypassword"))
            .unwrap();

        let loaded = Identity::load_with_password(&pub_path, &sec_path, "mypassword").unwrap();
        assert_eq!(loaded.encapsulation_key, identity.encapsulation_key);
        assert_eq!(
            loaded.decapsulation_key.as_slice(),
            identity.decapsulation_key.as_slice()
        );
    }

    #[test]
    fn test_identity_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let pub_path = tmp.path().join("identity.pub");
        let sec_path = tmp.path().join("identity");

        let identity = Identity::generate();
        identity
            .save(&pub_path, &sec_path, Some("correct"))
            .unwrap();

        let result = Identity::load_with_password(&pub_path, &sec_path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_no_password_file_has_no_embedded_key() {
        // این تست دقیقاً همون چیزی رو تضمین می‌کنه که رفع کردیم: توی حالت
        // بدون پسورد، دیگه هیچ "کلید ذخیره‌سازی" اضافه‌ای کنار داده رمزشده
        // نیست - فقط magic + فلگ + طول + خودِ کلید، بدون لایه‌ی رمزنگاری اضافی
        // this test confirms exactly what we fixed: in no-password mode there
        // is no longer an extra "storage key" sitting next to encrypted data -
        // just magic + flag + length + the raw key, no pointless crypto layer
        let tmp = TempDir::new().unwrap();
        let pub_path = tmp.path().join("identity.pub");
        let sec_path = tmp.path().join("identity");

        let identity = Identity::generate();
        identity.save(&pub_path, &sec_path, None).unwrap();

        let raw = fs::read(&sec_path).unwrap();
        assert_eq!(&raw[0..7], RIM1_MAGIC);
        assert_eq!(raw[7], PROTECTION_NONE);

        let dk_len = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        assert_eq!(dk_len, identity.decapsulation_key.len());
        assert_eq!(&raw[12..12 + dk_len], identity.decapsulation_key.as_slice());
    }

    #[test]
    fn test_identity_encapsulation_decapsulation() {
        let identity = Identity::generate();
        let (ct, ss1) = mlkem_hybrid::encapsulate(&identity.encapsulation_key).unwrap();
        let ss2 = mlkem_hybrid::decapsulate(identity.decapsulation_key.as_slice(), &ct).unwrap();
        assert_eq!(ss1, ss2);
    }
}
