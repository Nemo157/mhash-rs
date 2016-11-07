use sodiumoxide::crypto::hash::{ sha256, sha512 };

use validation;
use MultiHash;

pub fn validate_sha256(multihash: &MultiHash, data: &[u8]) -> validation::Result {
    validation::validate_base(multihash, &sha256::hash(data).0)
}

pub fn validate_sha512(multihash: &MultiHash, data: &[u8]) -> validation::Result {
    validation::validate_base(multihash, &sha512::hash(data).0)
}
