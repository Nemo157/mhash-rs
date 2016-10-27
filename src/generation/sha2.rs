use sodiumoxide::crypto::hash::{ sha256, sha512 };

use MultiHash;

pub fn generate_sha256(data: &[u8]) -> MultiHash {
    MultiHash::Sha2_256(sha256::hash(data).0, sha256::DIGESTBYTES)
}

pub fn generate_sha512(data: &[u8]) -> MultiHash {
    MultiHash::Sha2_512(sha512::hash(data).0, sha512::DIGESTBYTES)
}
