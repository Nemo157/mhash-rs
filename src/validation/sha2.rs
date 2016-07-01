use sodiumoxide::crypto::hash::{ sha256, sha512 };

use validation::{ self, Validator };

struct Sha256Validator;
struct Sha512Validator;

pub static SHA256_VALIDATOR: &'static Validator = &Sha256Validator;
pub static SHA512_VALIDATOR: &'static Validator = &Sha512Validator;

impl Validator for Sha256Validator {
    fn validate(&self, digest: &[u8], data: &[u8]) -> validation::Result {
        let hash = sha256::hash(data);
        if digest.len() > hash.as_ref().len() {
            return Err("Digest too long".into());
        }
        Ok(digest[..] == hash[..digest.len()])
    }
}

impl Validator for Sha512Validator {
    fn validate(&self, digest: &[u8], data: &[u8]) -> validation::Result {
        let hash = sha512::hash(data);
        if digest.len() > hash.as_ref().len() {
            return Err("Digest too long".into());
        }
        Ok(digest[..] == hash[..digest.len()])
    }
}
