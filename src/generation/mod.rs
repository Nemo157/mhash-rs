#[cfg(feature = "sha2")]
mod sha2;

use MultiHash;


impl MultiHash {
    #[cfg(all(feature = "generation", feature = "sha2"))]
    /// Generate a `MultiHash::Sha2_256` for the given data.
    pub fn generate_sha2_256(data: &[u8]) -> MultiHash {
        sha2::generate_sha256(data)
    }
}

impl MultiHash {
    #[cfg(all(feature = "generation", feature = "sha2"))]
    /// Generate a `MultiHash::Sha2_512` for the given data.
    pub fn generate_sha2_512(data: &[u8]) -> MultiHash {
        sha2::generate_sha512(data)
    }
}
