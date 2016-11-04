use std::fmt;

use error;
use MultiHashVariant;

/// A decoded multihash.
#[derive(Eq, Clone, Copy)]
pub struct MultiHash<D: AsRef<[u8]>> {
    variant: MultiHashVariant,
    digest: D,
}

#[allow(len_without_is_empty)]
impl<D: AsRef<[u8]>> MultiHash<D> {
    /// Create a new multihash with the specified variant and digest. Validates
    /// the length of the digest is consistent with the multihash variant.
    pub fn new(variant: MultiHashVariant, bytes: D) -> error::creation::Result<MultiHash<D>> {
        variant.check_length(bytes.as_ref().len())?;
        Ok(MultiHash { variant: variant, digest: bytes })
    }

    /// Create a new multihash with the specified code and digest, validates
    /// that the code is known or an application specific variant, and that the
    /// length is consistent with the multihash variant the code refers to.
    pub fn new_with_code(code: usize, bytes: D) -> error::creation::Result<MultiHash<D>> {
        let variant = MultiHashVariant::from_code(code)?;
        MultiHash::new(variant, bytes)
    }

    /// The length of this multihash's digest.
    pub fn len(&self) -> usize {
        self.digest.as_ref().len()
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
        self.digest.as_ref()
    }
}

impl<D: AsRef<[u8]>> fmt::Debug for MultiHash<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())?;
        f.write_str("(\"")?;
        for byte in self.digest() {
            write!(f, "{:x}", byte)?;
        }
        f.write_str("\")")?;
        Ok(())
    }
}

impl<D: AsRef<[u8]>, E: AsRef<[u8]>> PartialEq<MultiHash<E>> for MultiHash<D> {
    fn eq(&self, other: &MultiHash<E>) -> bool {
        self.variant == other.variant && self.digest() == other.digest()
    }
}
