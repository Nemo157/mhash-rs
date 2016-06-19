#[cfg(all(feature = "validation", feature = "validation_sha2"))]
use std::borrow::Cow;

use Digest;
#[cfg(all(feature = "validation", feature = "validation_sha2"))]
use validation::VALIDATORS;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MultiHash {
    length: usize,
    digest: Digest,
}

impl MultiHash {
    pub fn new(length: usize, digest: Digest) -> MultiHash {
        MultiHash {
            length: length,
            digest: digest,
        }
    }

    pub fn code(&self) -> u8 {
        self.digest.code()
    }

    pub fn name(&self) -> &'static str {
        self.digest.name()
    }

    pub fn digest_bytes(&self) -> &[u8] {
        &self.digest.bytes()[..self.length]
    }

    pub fn digest_length(&self) -> usize {
        self.length
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The length of this multihash when writing to a byte stream
    pub fn total_length(&self) -> usize {
        self.length + 2
    }

    #[cfg(all(feature = "validation", feature = "validation_sha2"))]
    pub fn validate(&self, data: &[u8]) -> Result<bool, Cow<'static, str>> {
        let validator = try!(VALIDATORS.get(self.code()).ok_or_else(|| Cow::Borrowed("no validator")));
        validator.validate(self.digest_bytes(), data)
    }
}
