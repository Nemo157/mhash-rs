#![feature(conservative_impl_trait)]
#![feature(slice_patterns)]

extern crate futures;
extern crate tokio_ext;

#[cfg(feature = "sha2")]
extern crate sodiumoxide;

mod digest;
mod multihash;

mod read;
// mod write;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(feature = "generation")]
pub mod generation;

pub use digest::Digest;
pub use multihash::MultiHash;

pub use read::read_multihash;
// pub use write::WriteMultiHash;
