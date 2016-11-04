#[cfg(feature = "sha2")]
mod sha2;

use std::borrow::Cow;
use std::result;

use MultiHash;

pub type Error = Cow<'static, str>; // TODO: Real error type
pub type Result = result::Result<bool, Error>;

impl<D: AsRef<[u8]>> MultiHash<D> {
    /// Returns None if there is no validator for this digest type, otherwise
    /// the result of the validator
    pub fn validate<E: AsRef<[u8]>>(&self, data: E) -> Option<Result> {
        use MultiHashVariant::*;
        let data = data.as_ref();
        match self.variant() {
            Sha2_256 => validate_sha256(self, data),
            Sha2_512 => validate_sha512(self, data),
            _ => None
        }
    }
}

macro_rules! optional_validator {
    ($f:expr, $m:ident, $n:ident) => {
        #[cfg(not(feature = $f))]
        pub fn $n<D: AsRef<[u8]>>(_multihash: &MultiHash<D>, _data: &[u8]) -> Option<Result> {
            None
        }

        #[cfg(feature = $f)]
        pub fn $n<D: AsRef<[u8]>>(multihash: &MultiHash<D>, data: &[u8]) -> Option<Result> {
            Some($m::$n(multihash, data))
        }
    };
}

macro_rules! optional_validators {
    ($f:expr, $m:ident, $($n:ident),+) => {
        $(optional_validator!($f, $m, $n);)*
    };
}

optional_validators!("sha2", sha2, validate_sha256, validate_sha512);

#[allow(dead_code)] // Will be dead if no validators are active
fn validate_base<D: AsRef<[u8]>>(multihash: &MultiHash<D>, hash: &[u8]) -> Result {
    if multihash.len() > hash.len() {
        return Err("Digest too long".into());
    }
    Ok(multihash.digest() == &hash[..multihash.len()])
}

