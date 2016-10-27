#[cfg(feature = "sha2")]
mod sha2;

#[cfg(feature = "sha2")]
pub use self::sha2::{ generate_sha256, generate_sha512 };

use MultiHash;

// Default algorithm is sha256 for now...
#[cfg(feature = "sha2")]
pub fn generate_default(data: &[u8]) -> MultiHash {
    generate_sha256(data)
}
