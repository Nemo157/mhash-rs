#[cfg(feature = "sha2")]
mod sha2;

use std::borrow::Cow;
use std::result;

use MultiHash;

pub type Error = Cow<'static, str>; // TODO: Real error type
pub type Result = result::Result<bool, Error>;

impl MultiHash {
    /// Returns None if there is no validator for this digest type, otherwise
    /// the result of the validator
    pub fn validate(&self, data: &[u8]) -> Option<Result> {
        use MultiHashVariant::*;
        match self.variant() {
            Sha2_256 => validate_sha256(self, data),
            Sha2_512 => validate_sha512(self, data),
            _ => None
        }
    }
}

macro_rules! optional_validator {
    ($feature:expr, $module:ident, $method:ident) => {
        #[cfg(not(feature = $feature))]
        pub fn $method(_multihash: &MultiHash, _data: &[u8]) -> Option<Result> {
            None
        }

        #[cfg(feature = $feature)]
        pub fn $method(multihash: &MultiHash, data: &[u8]) -> Option<Result> {
            Some($module::$method(multihash, data))
        }
    };
}

macro_rules! optional_validators {
    ($feature:expr, $module:ident, $($method:ident),+) => {
        $(optional_validator!($feature, $module, $method);)*
    };
}

optional_validators!("sha2", sha2, validate_sha256, validate_sha512);

#[allow(dead_code)] // Will be dead if no validators are active
fn validate_base(multihash: &MultiHash, hash: &[u8]) -> Result {
    if multihash.len() > hash.len() {
        return Err("Digest too long".into());
    }
    Ok(multihash.digest() == &hash[..multihash.len()])
}

