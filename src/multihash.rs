use digest::Digest;
#[cfg(feature = "generation")] use generation;
#[cfg(feature = "validation")] use validation;

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

    #[cfg(feature = "generation")]
    fn new_full_digest(digest: Digest) -> MultiHash {
        MultiHash {
            length: digest.bytes().len(),
            digest: digest,
        }
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    // Default algorithm is sha256 for now...
    pub fn generate(data: &[u8]) -> MultiHash {
        MultiHash::new_full_digest(generation::generate_sha256(data))
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha256(data: &[u8]) -> MultiHash {
        MultiHash::new_full_digest(generation::generate_sha256(data))
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha512(data: &[u8]) -> MultiHash {
        MultiHash::new_full_digest(generation::generate_sha512(data))
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

    /// Returns None if there is no validator for this digest type, otherwise
    /// the result of the validator
    #[cfg(feature = "validation")]
    pub fn validate(&self, data: &[u8]) -> Option<validation::Result> {
        validation::validate(self, data)
    }
}
