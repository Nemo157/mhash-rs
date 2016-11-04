use sodiumoxide::crypto::hash::{ sha256, sha512 };

use validation;
use MultiHash;

pub fn validate_sha256<D: AsRef<[u8]>>(multihash: &MultiHash<D>, data: &[u8]) -> validation::Result {
    validation::validate_base(multihash, &sha256::hash(data).0)
}

pub fn validate_sha512<D: AsRef<[u8]>>(multihash: &MultiHash<D>, data: &[u8]) -> validation::Result {
    validation::validate_base(multihash, &sha512::hash(data).0)
}
