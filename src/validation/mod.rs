#[cfg(feature = "validation_sha2")]
mod sha2;

use std::borrow::Cow;
use std::result;

use digest::Digest;

pub type Error = Cow<'static, str>; // TODO: Real error type
pub type Result = result::Result<bool, Error>;

pub trait Validator: Sync {
    fn validate(&self, digest: &[u8], data: &[u8]) -> Result;
}

#[cfg(not(feature = "validation_sha2"))]
pub fn get_validator(_digest: &Digest) -> Option<&'static Validator> {
    None
}

#[cfg(feature = "validation_sha2")]
pub fn get_validator(digest: &Digest) -> Option<&'static Validator> {
    use digest::Digest::*;
    Some(match *digest {
        Sha2_256(_) => sha2::SHA256_VALIDATOR,
        Sha2_512(_) => sha2::SHA512_VALIDATOR,
        _ => { return None; }
    })
}
