use std::fmt;
use std::hash::{ Hash, Hasher };

use varmint::{ self, ReadVarInt, WriteVarInt };

use error;
use MultiHash::*;

/// A decoded multihash.
#[allow(non_camel_case_types)]
pub enum MultiHash {
    /// A straight copy of the data supposedly hashed.
    /// May be a prefix rather than a full copy.
    Identity(Vec<u8>),

    /// A 160-bit [SHA-1][] digest + length.
    /// [SHA-1]: https://en.wikipedia.org/wiki/SHA-1
    Sha1([u8; 20], usize),

    /// A 256-bit [SHA-2][] digest + length.
    /// [SHA-2]: https://en.wikipedia.org/wiki/SHA-2
    Sha2_256([u8; 32], usize),

    /// A 512-bit [SHA-2][] digest + length.
    /// [SHA-2]: https://en.wikipedia.org/wiki/SHA-2
    Sha2_512([u8; 64], usize),

    /// A 512-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_512([u8; 64], usize),

    /// A 384-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_384([u8; 48], usize),

    /// A 256-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_256([u8; 32], usize),

    /// A 224-bit [SHA-3][] digest + length.
    /// [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
    Sha3_224([u8; 28], usize),

    /// A variable size [SHAKE-128][] digest.
    /// [SHAKE-128]: https://en.wikipedia.org/wiki/SHA-3
    Shake128(Vec<u8>),

    /// A variable size [SHAKE-256][] digest.
    /// [SHAKE-256]: https://en.wikipedia.org/wiki/SHA-3
    Shake256(Vec<u8>),

    /// A 512-bit [BLAKE2b][] digest.
    /// [BLAKE2b]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
    Blake2B([u8; 64], usize),

    /// A 256-bit [BLAKE2s][] digest.
    /// [BLAKE2s]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
    Blake2S([u8; 32], usize),

    /// An application specific MultiHash variant.
    ApplicationSpecific {
        /// The application specific code for this variant, must be in the
        /// range [0x0400, 0x040f].
        code: usize,

        /// The digest for this hash.
        bytes: Vec<u8>,
    },
}

#[allow(len_without_is_empty)]
impl MultiHash {
    /// Parse a binary encoded multihash
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> error::from_bytes::Result<MultiHash> {
        let mut bytes = &mut bytes.as_ref();
        let code = bytes.read_usize_varint()?;
        let length = bytes.read_usize_varint()?;
        let mut hash = MultiHash::from_code_and_length(code, length)?;
        hash.digest_mut()[..length].copy_from_slice(bytes);
        Ok(hash)
    }

    // TODO: Correctly use errors
    /// Create an empty multihash with the specified code and length, validates
    /// that the code is known or an application specific variant, and that the
    /// length is consistent with the multihash variant the code refers to.
    pub fn from_code_and_length(code: usize, length: usize) -> error::creation::Result<MultiHash> {
        macro_rules! array_kind {
            ($k:ident($l:expr)) => (
                if length <= $l {
                    $k([0; $l], length)
                } else {
                    return Err(error::creation::ErrorKind::LengthTooLong(length, $l, stringify!($k)).into());
                }
            )
        }
        Ok(match code {
            0x00 => Identity(vec![0; length]),
            0x11 => array_kind!(Sha1(20)),
            0x12 => array_kind!(Sha2_256(32)),
            0x13 => array_kind!(Sha2_512(64)),
            0x14 => array_kind!(Sha3_512(64)),
            0x15 => array_kind!(Sha3_384(48)),
            0x16 => array_kind!(Sha3_256(32)),
            0x17 => array_kind!(Sha3_224(28)),
            0x18 => Shake128(vec![0; length]),
            0x19 => Shake256(vec![0; length]),

            0x40 => array_kind!(Blake2B(64)),
            0x41 => array_kind!(Blake2S(32)),

            _ if code > 0x0400 && code < 0x040f =>
                ApplicationSpecific { code: code, bytes: vec![0; length] },
            _ => {
                return Err(error::creation::ErrorKind::UnknownCode(code).into());
            }
        })
    }

    /// The length of this multihash's digest.
    pub fn len(&self) -> usize {
        match *self {
            Sha1(_, length)
                | Sha2_256(_, length)
                | Sha2_512(_, length)
                | Sha3_224(_, length)
                | Sha3_256(_, length)
                | Sha3_384(_, length)
                | Sha3_512(_, length)
                | Blake2B(_, length)
                | Blake2S(_, length)
                => length,
            Identity(ref bytes)
                | Shake128(ref bytes)
                | Shake256(ref bytes)
                | ApplicationSpecific { ref bytes, .. }
                => bytes.len(),
        }
    }

    /// The code specifying this multihash variant.
    pub fn code(&self) -> usize {
        match *self {
            Identity(..) => 0x00,
            Sha1(..) => 0x11,
            Sha2_256(..) => 0x12,
            Sha2_512(..) => 0x13,
            Sha3_512(..) => 0x14,
            Sha3_384(..) => 0x15,
            Sha3_256(..) => 0x16,
            Sha3_224(..) => 0x17,
            Shake128(..) => 0x18,
            Shake256(..) => 0x19,
            Blake2B(..) => 0x40,
            Blake2S(..) => 0x41,

            ApplicationSpecific { code, .. } if code > 0x0400 && code < 0x040f => {
                code
            }

            // TODO: could just ignore them being invalid or return Error...
            ApplicationSpecific { code, .. } => {
                panic!("application specific code {:#04x} outside allowed range 0x0400-0x040f", code)
            }
        }
    }

    /// The string representation of this multihash type.
    pub fn name(&self) -> &'static str {
        match *self {
            Identity(..) => "identity",
            Sha1(..) => "sha1",
            Sha2_256(..) => "sha2-256",
            Sha2_512(..) => "sha2-512",
            Sha3_224(..) => "sha3-224",
            Sha3_256(..) => "sha3-256",
            Sha3_384(..) => "sha3-384",
            Sha3_512(..) => "sha3-512",
            Shake128(..) => "shake-128",
            Shake256(..) => "shake-256",
            Blake2B(..) => "blake2b",
            Blake2S(..) => "blake2s",

            ApplicationSpecific { code, .. } if code > 0x0400 && code < 0x040f => "app-specific",
            _ => panic!("TODO: not panic"),
        }
    }

    /// A reference to the bytes making up the digest of this multihash.
    pub fn digest(&self) -> &[u8] {
        match *self {
            Sha1(ref bytes, length) => &bytes[..length],
            Sha3_224(ref bytes, length) => &bytes[..length],
            Sha3_384(ref bytes, length) => &bytes[..length],
            Sha2_512(ref bytes, length)
                | Sha3_512(ref bytes, length)
                | Blake2B(ref bytes, length)
                => &bytes[..length],
            Sha2_256(ref bytes, length)
                | Sha3_256(ref bytes, length)
                | Blake2S(ref bytes, length)
                => &bytes[..length],
            Identity(ref bytes)
                | Shake128(ref bytes)
                | Shake256(ref bytes)
                | ApplicationSpecific { ref bytes, .. }
                => bytes,
        }
    }

    /// A mutable reference to the bytes making up the digest of this multihash.
    pub fn digest_mut(&mut self) -> &mut [u8] {
        match *self {
            Sha1(ref mut bytes, length) => &mut bytes[..length],
            Sha3_224(ref mut bytes, length) => &mut bytes[..length],
            Sha3_384(ref mut bytes, length) => &mut bytes[..length],
            Sha2_512(ref mut bytes, length)
                | Sha3_512(ref mut bytes, length)
                | Blake2B(ref mut bytes, length)
                => &mut bytes[..length],
            Sha2_256(ref mut bytes, length)
                | Sha3_256(ref mut bytes, length)
                | Blake2S(ref mut bytes, length)
                => &mut bytes[..length],
            Identity(ref mut bytes)
                | Shake128(ref mut bytes)
                | Shake256(ref mut bytes)
                | ApplicationSpecific { ref mut bytes, .. }
                => bytes,
        }
    }

    /// Create a `Vec<u8>` with the binary encoding of this multihash.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.output_len());
        {
            let mut writer = &mut bytes;
            writer.write_usize_varint(self.code()).unwrap();
            writer.write_usize_varint(self.len()).unwrap();
        }
        bytes.extend_from_slice(self.digest());
        bytes
    }

    /// The length this multihash will use when serialized to a byte
    /// array/stream.
    pub fn output_len(&self) -> usize {
        varmint::len_usize_varint(self.code())
            + varmint::len_usize_varint(self.len())
            + self.len()
    }
}

impl fmt::Debug for MultiHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())?;
        f.write_str("(\"")?;
        for byte in self.digest() {
            write!(f, "{:x}", byte)?;
        }
        f.write_str("\")")?;
        Ok(())
    }
}

impl Clone for MultiHash {
    fn clone(&self) -> MultiHash {
        match *self {
            Identity(ref bytes) => Identity(bytes.clone()),
            Sha1(ref bytes, length) => Sha1(*bytes, length),
            Sha2_256(ref bytes, length) => Sha2_256(*bytes, length),
            Sha2_512(ref bytes, length) => Sha2_512(*bytes, length),
            Sha3_224(ref bytes, length) => Sha3_224(*bytes, length),
            Sha3_256(ref bytes, length) => Sha3_256(*bytes, length),
            Sha3_384(ref bytes, length) => Sha3_384(*bytes, length),
            Sha3_512(ref bytes, length) => Sha3_512(*bytes, length),
            Shake128(ref bytes) => Shake128(bytes.clone()),
            Shake256(ref bytes) => Shake256(bytes.clone()),
            Blake2B(ref bytes, length) => Blake2B(*bytes, length),
            Blake2S(ref bytes, length) => Blake2S(*bytes, length),
            ApplicationSpecific { code, ref bytes } => ApplicationSpecific {
                code: code,
                bytes: bytes.clone(),
            },
        }
    }
}

impl Eq for MultiHash {}
impl PartialEq for MultiHash {
    fn eq(&self, other: &MultiHash) -> bool {
        self.code() == other.code() && self.digest() == other.digest()
    }
}

impl Hash for MultiHash {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        state.write_usize(self.code());
        state.write_usize(self.len());
        state.write(self.digest());
    }
}

#[cfg(test)]
mod tests {
    use MultiHash;

    #[test]
    fn to_bytes() {
        let multihash = MultiHash::Sha1([
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ], 4);
        assert_eq!(
            multihash.to_bytes(),
            vec![0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn to_bytes_with_varint() {
        let multihash = MultiHash::ApplicationSpecific {
            code: 0x0401,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(
            multihash.to_bytes(),
            vec![0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_bytes() {
        let multihash = MultiHash::Sha1([
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ], 4);
        assert_eq!(
            multihash,
            MultiHash::from_bytes([0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]).unwrap());
    }

    #[test]
    fn from_bytes_with_varint() {
        let multihash = MultiHash::ApplicationSpecific {
            code: 0x0401,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(
            multihash,
            MultiHash::from_bytes([0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]).unwrap());
    }
}
