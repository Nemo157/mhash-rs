use sodiumoxide::crypto::hash::{ sha256, sha512 };

use super::Array64;
use { MultiHash, MultiHashVariant };

pub fn generate_sha256(data: &[u8]) -> MultiHash<[u8; 32]> {
    let digest = sha256::hash(data).0;
    MultiHash::new(MultiHashVariant::Sha2_256, digest).unwrap()
}

pub fn generate_sha512(data: &[u8]) -> MultiHash<Array64> {
    let digest = Array64(sha512::hash(data).0);
    MultiHash::new(MultiHashVariant::Sha2_512, digest).unwrap()
}
