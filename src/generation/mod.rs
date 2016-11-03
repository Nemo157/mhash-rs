#[cfg(feature = "sha2")]
mod sha2;

use MultiHash;

impl MultiHash {
    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha256<D: AsRef<[u8]>>(data: D) -> MultiHash {
        sha2::generate_sha256(data.as_ref())
    }

    #[cfg(all(feature = "generation", feature = "sha2"))]
    pub fn generate_sha512<D: AsRef<[u8]>>(data: D) -> MultiHash {
        sha2::generate_sha512(data.as_ref())
    }
}
