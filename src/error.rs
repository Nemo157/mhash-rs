#![allow(trivial_casts)] // Caused by error_chain!
#![allow(missing_docs)] // Caused by error_chain!
#![allow(redundant_closure)] // Caused by error_chain!

pub mod creation {
    use MultiHashVariant;

    error_chain! {
        errors {
            LengthTooLong(variant: MultiHashVariant, length: usize) {
                description("multihash length too long")
                display(
                    "multihash length {} longer than max length {} for hash kind {}",
                    length, variant.max_len(), variant.name())
            }
            UnknownCode(code: usize) {
                description("unknown multihash code")
                display("unknown multihash code: {}", code)
            }
        }
    }
}

#[cfg(feature = "vec")]
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

        errors {
            WrongLengthGiven(length: usize, expected_length: usize) {
                description("given slice was the wrong length")
                display(
                    "given slice had {} bytes of digest but contained a multihash with a {} byte digest",
                    length, expected_length)
            }
        }
    }
}

#[cfg(feature = "str")]
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

