#[cfg(feature = "sha2")]
extern crate sodiumoxide;

mod digest;
mod multihash;

mod read;
mod write;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(feature = "generation")]
pub mod generation;

pub use digest::Digest;
pub use multihash::MultiHash;

pub use read::ReadMultiHash;
pub use write::WriteMultiHash;
