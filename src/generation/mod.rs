#[cfg(feature = "sha2")]
mod sha2;

#[cfg(feature = "sha2")]
pub use self::sha2::{ generate_sha256, generate_sha512 };
