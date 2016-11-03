#![allow(trivial_casts)] // Caused by error_chain!
#![allow(missing_docs)] // Caused by error_chain!

pub mod creation {
    error_chain! {
        errors {
            LengthTooLong(length: usize, max_length: usize, kind: &'static str) {
                description("multihash length too long")
                display(
                    "multihash length {} longer than max length {} for hash kind {}",
                    length, max_length, kind)
            }
            UnknownCode(code: usize) {
                description("unknown multihash code")
                display("unknown multihash code: {}", code)
            }
        }
    }
}

pub mod from_bytes {
    use std::io;
    use super::creation;

    error_chain! {
        links {
            creation::Error, creation::ErrorKind, Creation;
        }

        foreign_links {
            io::Error, Io;
        }
    }
}

#[cfg(feature = "parse")]
pub mod parse {
    use bs58;
    use super::from_bytes;

    error_chain! {
        links {
            from_bytes::Error, from_bytes::ErrorKind, FromBytes;
        }

        foreign_links {
            bs58::FromBase58Error, Base58;
        }
    }
}

