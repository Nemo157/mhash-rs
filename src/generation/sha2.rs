use sodiumoxide::crypto::hash::{ sha256, sha512 };

use { MultiHash, MultiHashVariant };

pub fn generate_sha256(data: &[u8]) -> MultiHash {
    let digest = sha256::hash(data).0;
    MultiHash::new(MultiHashVariant::Sha2_256, &digest).unwrap()
}

pub fn generate_sha512(data: &[u8]) -> MultiHash {
    let digest = sha512::hash(data).0;
    MultiHash::new(MultiHashVariant::Sha2_512, &digest).unwrap()
}
