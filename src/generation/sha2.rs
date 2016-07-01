use sodiumoxide::crypto::hash::{ sha256, sha512 };

use digest::Digest;
use generation;

pub fn generate_sha256(data: &[u8]) -> generation::Result {
    Ok(Digest::Sha2_256(sha256::hash(data).0))
}

pub fn generate_sha512(data: &[u8]) -> generation::Result {
    Ok(Digest::Sha2_512(sha512::hash(data).0))
}
