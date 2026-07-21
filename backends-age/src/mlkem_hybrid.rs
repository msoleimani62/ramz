use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug)]
pub struct MlKemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Zeroize for MlKemKeyPair {
    fn zeroize(&mut self) {
        self.public_key.zeroize();
        self.secret_key.zeroize();
    }
}

impl ZeroizeOnDrop for MlKemKeyPair {}

pub fn generate_keypair() -> MlKemKeyPair {
    // uses the crate's internal system-secure RNG via the `getrandom` feature
    // استفاده از رابط داخلی crate برای تولید کلید با تصادفی‌ساز امن سیستم
    let (dk, ek) = MlKem768::generate_keypair();
    MlKemKeyPair {
        public_key: ek.to_bytes().to_vec(),
        secret_key: dk.to_bytes().to_vec(),
    }
}

pub fn encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_bytes = public_key_bytes
        .try_into()
        .map_err(|_| "invalid public key length".to_string())?;

    let ek = EncapsulationKey::<MlKem768>::new(&key_bytes)
        .map_err(|_| "invalid public key".to_string())?;

    // the new encapsulate() signature no longer takes a manual rng
    // امضای جدید encapsulate() دیگه rng دستی نمی‌گیره
    let (ciphertext, shared_secret): (Ciphertext<MlKem768>, _) = ek.encapsulate();

    Ok((
        AsRef::<[u8]>::as_ref(&ciphertext).to_vec(),
        shared_secret.to_vec(),
    ))
}

pub fn decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let seed = secret_key_bytes
        .try_into()
        .map_err(|_| "invalid secret key length".to_string())?;

    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);

    let ciphertext: Ciphertext<MlKem768> = ciphertext_bytes
        .try_into()
        .map_err(|_| "invalid ciphertext length".to_string())?;

    let shared_secret = dk.decapsulate(&ciphertext);

    Ok(shared_secret.to_vec())
}

pub fn combine_secrets(x25519_secret: &[u8], mlkem_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x25519_secret);
    hasher.update(mlkem_secret);

    let result = hasher.finalize();

    let mut combined = [0u8; 32];
    combined.copy_from_slice(&result);

    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_roundtrip() {
        let keypair = generate_keypair();

        let (ciphertext, shared_secret_enc) = encapsulate(&keypair.public_key).unwrap();

        let shared_secret_dec = decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_combine_secrets_deterministic() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];

        let c1 = combine_secrets(&s1, &s2);
        let c2 = combine_secrets(&s1, &s2);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_inputs_different_combined() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let s3 = [3u8; 32];

        let c1 = combine_secrets(&s1, &s2);
        let c2 = combine_secrets(&s1, &s3);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_keypair_sizes() {
        let kp = generate_keypair();

        assert_eq!(kp.public_key.len(), 1184);
        assert_eq!(kp.secret_key.len(), 64);
    }

    #[test]
    fn test_encapsulate_output_sizes() {
        let kp = generate_keypair();

        let (ct, ss) = encapsulate(&kp.public_key).unwrap();

        assert_eq!(ct.len(), 1088);
        assert_eq!(ss.len(), 32);
    }
}
