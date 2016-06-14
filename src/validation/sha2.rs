use sodiumoxide::crypto::hash::{ sha256, sha512 };

use std::borrow::Cow;
use super::Validator;

pub struct Sha256Validator;
pub struct Sha512Validator;

pub static SHA256_VALIDATOR: Sha256Validator = Sha256Validator;
pub static SHA512_VALIDATOR: Sha512Validator = Sha512Validator;

impl Validator for Sha256Validator {
    fn validate(&self, digest: &[u8], data: &[u8]) -> Result<bool, Cow<'static, str>> {
        let hash = sha256::hash(data);
        if digest.len() > hash.as_ref().len() { return Err("Digest too long".into()); }
        Ok(digest[..] == hash[..digest.len()])
    }
}

impl Validator for Sha512Validator {
    fn validate(&self, digest: &[u8], data: &[u8]) -> Result<bool, Cow<'static, str>> {
        let hash = sha512::hash(data);
        if digest.len() > hash.as_ref().len() { return Err("Digest too long".into()); }
        Ok(digest[..] == hash[..digest.len()])
    }
}
