#[cfg(feature = "sha2")]
mod sha2;

use std::borrow::Cow;
use std::result;

use MultiHash;

pub type Error = Cow<'static, str>; // TODO: Real error type
pub type Result = result::Result<bool, Error>;

#[cfg(not(feature = "sha2"))]
pub fn validate(_multihash: &MultiHash, _data: &[u8]) -> Option<Result> {
    None
}

#[cfg(feature = "sha2")]
pub fn validate(multihash: &MultiHash, data: &[u8]) -> Option<Result> {
    use digest::Digest::*;
    Some(match *multihash.digest() {
        Sha2_256(_) => sha2::validate_sha256(multihash, data),
        Sha2_512(_) => sha2::validate_sha512(multihash, data),
        _ => { return None; }
    })
}

#[cfg(feature = "sha2")]
fn validate_base(multihash: &MultiHash, hash: &[u8]) -> Result {
    if multihash.digest_length() > hash.len() {
        return Err("Digest too long".into());
    }
    Ok(multihash.digest_bytes() == &hash[..multihash.digest_length()])
}
