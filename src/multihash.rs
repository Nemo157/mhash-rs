use digest::Digest;
#[cfg(feature = "generation")] use generation;
#[cfg(feature = "validation")] use validation;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MultiHash {
    digest: Digest,
}

impl MultiHash {
    pub fn new(digest: Digest) -> MultiHash {
        MultiHash {
            digest: digest,
        }
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    // Default algorithm is sha256 for now...
    pub fn generate<D: AsRef<[u8]>>(data: D) -> MultiHash {
        MultiHash::new(generation::generate_sha256(data.as_ref()))
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha256<D: AsRef<[u8]>>(data: D) -> MultiHash {
        MultiHash::new(generation::generate_sha256(data.as_ref()))
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha512<D: AsRef<[u8]>>(data: D) -> MultiHash {
        MultiHash::new(generation::generate_sha512(data.as_ref()))
    }

    pub fn code(&self) -> u8 {
        self.digest.code()
    }

    pub fn name(&self) -> &'static str {
        self.digest.name()
    }

    pub fn digest_bytes(&self) -> &[u8] {
        &self.digest.as_ref()
    }

    pub fn digest_length(&self) -> usize {
        self.digest.len()
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The length of this multihash when writing to a byte stream
    pub fn total_length(&self) -> usize {
        self.digest_length() + 2
    }

    /// Returns None if there is no validator for this digest type, otherwise
    /// the result of the validator
    #[cfg(feature = "validation")]
    pub fn validate<D: AsRef<[u8]>>(&self, data: D) -> Option<validation::Result> {
        validation::validate(self, data.as_ref())
    }
}
