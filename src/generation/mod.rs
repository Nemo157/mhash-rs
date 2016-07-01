#[cfg(feature = "sha2")]
mod sha2;

use std::borrow::Cow;
use std::result;

use digest::Digest;

#[cfg(feature = "sha2")]
pub use self::sha2::{ generate_sha256, generate_sha512 };

pub type Error = Cow<'static, str>; // TODO: Real error type
pub type Result = result::Result<Digest, Error>;

#[cfg(not(feature = "sha2"))]
pub fn generate(_data: &[u8]) -> Result {
    Err("No generation algorithms included".into())
}

#[cfg(feature = "sha2")]
pub fn generate(data: &[u8]) -> Result {
    generate_sha256(data)
}
