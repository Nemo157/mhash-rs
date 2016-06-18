#[cfg(feature = "validation")]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "validation_sha2")]
extern crate sodiumoxide;

mod code;
mod multihash;
mod read;
mod write;
#[cfg(feature = "validation")]
pub mod validation;

pub use code::{ BlockSize, ShaVariant, Blake2Variant, Code };
pub use multihash::MultiHash;
pub use read::ReadMultiHash;
pub use write::WriteMultiHash;
