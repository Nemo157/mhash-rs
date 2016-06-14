#[cfg(feature = "validation")]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "validation_sha2")]
extern crate sodiumoxide;

mod code;
mod multihash;
#[cfg(feature = "validation")]
pub mod validation;

pub use code::*;
pub use multihash::*;
