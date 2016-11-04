#[cfg(feature = "sha2")]
mod sha2;

use MultiHash;

#[allow(dead_code)]
#[allow(missing_copy_implementations)]
#[allow(missing_debug_implementations)]
pub struct Array64([u8; 64]);
impl AsRef<[u8]> for Array64 { fn as_ref(&self) -> &[u8] { &self.0 } }

impl MultiHash<[u8; 32]> {
    #[cfg(all(feature = "generation", feature = "sha2"))]
    /// Generate a `MultiHash::Sha2_256` for the given data.
    pub fn generate_sha2_256<D: AsRef<[u8]>>(data: D) -> MultiHash<[u8; 32]> {
        sha2::generate_sha256(data.as_ref())
    }
}

impl MultiHash<Array64> {
    #[cfg(all(feature = "generation", feature = "sha2"))]
    /// Generate a `MultiHash::Sha2_512` for the given data.
    pub fn generate_sha2_512<D: AsRef<[u8]>>(data: D) -> MultiHash<Array64> {
        sha2::generate_sha512(data.as_ref())
    }
}
