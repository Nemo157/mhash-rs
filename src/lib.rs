#![feature(conservative_impl_trait)]
#![feature(slice_patterns)]

#![cfg_attr(feature = "parse", recursion_limit = "1024")]

#![allow(unknown_lints)] // for clippy
#![warn(fat_ptr_transmutes)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_results)]
#![warn(variant_size_differences)]

//! An implementation of the [multihash][] format as used in [IPFS][].
//!
//! [multihash]: https://github.com/multiformats/multihash
//! [ipfs]: https://ipfs.io

#[cfg(feature = "sha2")]
extern crate sodiumoxide;

#[cfg(any(feature = "parse", feature = "display"))]
extern crate bs58;

#[allow(unused_extern_crates)] // Only using a macro
#[macro_use]
extern crate error_chain;

extern crate varmint;

mod error;
mod multihash;

mod read;
mod write;

#[cfg(feature = "parse")]
mod parse;

#[cfg(feature = "display")]
mod display;

#[cfg(feature = "validation")]
mod validation;

#[cfg(feature = "generation")]
mod generation;

pub use multihash::MultiHash;

pub use read::ReadMultiHash;
pub use write::WriteMultiHash;
