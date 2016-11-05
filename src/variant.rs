use error;
use self::MultiHashVariant::*;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
/// The possible multihash variants.
pub enum MultiHashVariant {
    /// A straight copy of the data supposedly hashed.
    /// May be a prefix rather than a full copy.
    Identity,

    /// A 160-bit [SHA-1][] digest + length.
    /// [SHA-1]: https://en.wikipedia.org/wiki/SHA-1
    Sha1,

    /// A 256-bit [SHA-2][] digest + length.
    /// [SHA-2]: https://en.wikipedia.org/wiki/SHA-2
    Sha2_256,

    /// A 512-bit [SHA-2][] digest + length.
    /// [SHA-2]: https://en.wikipedia.org/wiki/SHA-2
    Sha2_512,

    /// A 512-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_512,

    /// A 384-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_384,

    /// A 256-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_256,

    /// A 224-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_224,

    /// A variable size [SHAKE-128][] digest.
    /// [SHAKE-128]: https://en.wikipedia.org/wiki/SHA-3
    Shake128,

    /// A variable size [SHAKE-256][] digest.
    /// [SHAKE-256]: https://en.wikipedia.org/wiki/SHA-3
    Shake256,

    /// A 512-bit [BLAKE2b][] digest.
    /// [BLAKE2b]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
    Blake2B,

    /// A 256-bit [BLAKE2s][] digest.
    /// [BLAKE2s]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
    Blake2S,

    /// An application specific MultiHash variant.
    ApplicationSpecific {
        /// The application specific code for this variant, must be in the
        /// range [0x0400, 0x040f].
        code: usize
    },

    #[doc(hidden)]
    /// Ensure extending this enum is a non-breaking change, unless users
    /// really want to break it...
    __Nonexhaustive,
}

impl MultiHashVariant {
    /// Returns the multihash variant that the given code refers to, validates
    /// that the code is known or an application specific variant.
    pub fn from_code(code: usize) -> error::creation::Result<MultiHashVariant> {
        Ok(match code {
            0x00 => Identity,
            0x11 => Sha1,
            0x12 => Sha2_256,
            0x13 => Sha2_512,
            0x14 => Sha3_512,
            0x15 => Sha3_384,
            0x16 => Sha3_256,
            0x17 => Sha3_224,
            0x18 => Shake128,
            0x19 => Shake256,

            0x40 => Blake2B,
            0x41 => Blake2S,

            0x0400 ... 0x040f => ApplicationSpecific { code: code },
            _ => {
                return Err(error::creation::ErrorKind::UnknownCode(code).into());
            }
        })
    }

    /// Returns the multihash variant that the given code refers to, validates
    /// that the code is known or an application specific variant, and that the
    /// length is consistent with the multihash variant the code refers to.
    pub fn from_code_and_length(code: usize, length: usize) -> error::creation::Result<MultiHashVariant> {
        let variant = try!(MultiHashVariant::from_code(code));
        try!(variant.check_length(length));
        Ok(variant)
    }

    /// Validates that the length is consistent with this multihash variant.
    pub fn check_length(self, length: usize) -> error::creation::Result<()> {
        if length > self.max_len() {
            Err(error::creation::ErrorKind::LengthTooLong(self, length).into())
        } else {
            Ok(())
        }
    }

    /// The maximum digest length allowed for this multihash variant.
    pub fn max_len(self) -> usize {
        match self {
            Identity => usize::max_value(),
            Sha1 => 20,
            Sha2_256 => 32,
            Sha2_512 => 64,
            Sha3_512 => 64,
            Sha3_384 => 48,
            Sha3_256 => 32,
            Sha3_224 => 28,
            Shake128 => usize::max_value(),
            Shake256 => usize::max_value(),
            Blake2B => 64,
            Blake2S => 32,
            ApplicationSpecific { .. } => usize::max_value(),
            __Nonexhaustive => unreachable!(),
        }
    }

    /// The code specifying this multihash variant.
    pub fn code(self) -> usize {
        match self {
            Identity => 0x00,
            Sha1 => 0x11,
            Sha2_256 => 0x12,
            Sha2_512 => 0x13,
            Sha3_512 => 0x14,
            Sha3_384 => 0x15,
            Sha3_256 => 0x16,
            Sha3_224 => 0x17,
            Shake128 => 0x18,
            Shake256 => 0x19,
            Blake2B => 0x40,
            Blake2S => 0x41,
            ApplicationSpecific { code } => {
                assert!(code > 0x0400 && code < 0x040f, "application specific code {:#04x} outside allowed range 0x0400-0x040f", code);
                code
            }
            __Nonexhaustive => unreachable!(),
        }
    }

    /// The string representation of this multihash type.
    pub fn name(self) -> &'static str {
        match self {
            Identity => "identity",
            Sha1 => "sha1",
            Sha2_256 => "sha2-256",
            Sha2_512 => "sha2-512",
            Sha3_224 => "sha3-224",
            Sha3_256 => "sha3-256",
            Sha3_384 => "sha3-384",
            Sha3_512 => "sha3-512",
            Shake128 => "shake-128",
            Shake256 => "shake-256",
            Blake2B => "blake2b",
            Blake2S => "blake2s",
            ApplicationSpecific { code } => {
                assert!(code > 0x0400 && code < 0x040f, "application specific code {:#04x} outside allowed range 0x0400-0x040f", code);
                "app-specific"
            }
            __Nonexhaustive => unreachable!(),
        }
    }

}

