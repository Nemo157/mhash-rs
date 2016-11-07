use std::fmt;

use smallvec::SmallVec;

use error;
use MultiHashVariant;

/// A decoded multihash.
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct MultiHash {
    variant: MultiHashVariant,
    digest: SmallVec<[u8; 64]>,
}

#[allow(len_without_is_empty)]
impl MultiHash {
    /// Create a new multihash with the specified variant and digest. Validates
    /// the length of the digest is consistent with the multihash variant.
    pub fn new(variant: MultiHashVariant, digest: &[u8]) -> error::creation::Result<MultiHash> {
        try!(variant.check_length(digest.len()));
        Ok(MultiHash { variant: variant, digest: digest.into() })
    }

    /// Create a new multihash with the specified code and digest, validates
    /// that the code is known or an application specific variant, and that the
    /// length is consistent with the multihash variant the code refers to.
    pub fn new_with_code(code: usize, digest: &[u8]) -> error::creation::Result<MultiHash> {
        let variant = try!(MultiHashVariant::from_code(code));
        MultiHash::new(variant, digest)
    }

    /// The length of this multihash's digest.
    pub fn len(&self) -> usize {
        self.digest.len()
    }

    /// This multihash's variant.
    pub fn variant(&self) -> MultiHashVariant {
        self.variant
    }

    /// The code specifying this multihash variant.
    pub fn code(&self) -> usize {
        self.variant.code()
    }

    /// The string representation of this multihash type.
    pub fn name(&self) -> &'static str {
        self.variant.name()
    }

    /// A reference to the bytes making up the digest of this multihash.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl fmt::Debug for MultiHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str(self.name()));
        try!(f.write_str("(\""));
        for byte in self.digest() {
            try!(write!(f, "{:x}", byte));
        }
        try!(f.write_str("\")"));
        Ok(())
    }
}
