use std::fmt;
use std::hash::{ Hash, Hasher };

use varmint::{ self, ReadVarInt, WriteVarInt };

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

impl MultiHash {
    /// Parse a binary encoded multihash
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<MultiHash, String> {
        let mut bytes = &mut bytes.as_ref();
        let code = bytes.read_usize_varint().map_err(|e| e.to_string())?;
        let length = bytes.read_usize_varint().map_err(|e| e.to_string())?;
        let mut hash = MultiHash::from_code_and_length(code, length)?;
        hash.digest_mut()[..length].copy_from_slice(bytes);
        Ok(hash)
    }

    // TODO: Real error type
    /// Create an empty multihash with the specified code and length, validates
    /// that the code is known or an application specific variant, and that the
    /// length is consistent with the multihash variant the code refers to.
    pub fn from_code_and_length(code: usize, length: usize) -> Result<MultiHash, &'static str> {
        Ok(match code {
            0x00 => Identity(vec![0; length]),
            0x11 if length <= 20 => Sha1([0; 20], length),
            0x12 if length <= 32 => Sha2_256([0; 32], length),
            0x13 if length <= 64 => Sha2_512([0; 64], length),
            0x14 if length <= 64 => Sha3_512([0; 64], length),
            0x15 if length <= 48 => Sha3_384([0; 48], length),
            0x16 if length <= 32 => Sha3_256([0; 32], length),
            0x17 if length <= 28 => Sha3_224([0; 28], length),
            0x18 => Shake128(vec![0; length]),
            0x19 => Shake256(vec![0; length]),

            0x40 if length <= 64 => Blake2B([0; 64], length),
            0x41 if length <= 32 => Blake2S([0; 32], length),

            _ if code > 0x0400 && code < 0x040f =>
                ApplicationSpecific { code: code, bytes: vec![0; length] },
            _ => {
                return Err("MultiHash length exceeds allowed length for specified type")
            }
        })
    }

    /// The length of this multihash's digest.
    pub fn len(&self) -> usize {
        match *self {
            Identity(ref bytes) => bytes.len(),
            Sha1(_, length) => length,
            Sha2_256(_, length) => length,
            Sha2_512(_, length) => length,
            Sha3_224(_, length) => length,
            Sha3_256(_, length) => length,
            Sha3_384(_, length) => length,
            Sha3_512(_, length) => length,
            Shake128(ref bytes) => bytes.len(),
            Shake256(ref bytes) => bytes.len(),
            Blake2B(_, length) => length,
            Blake2S(_, length) => length,
            ApplicationSpecific { ref bytes, .. } => bytes.len(),
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
            Identity(ref bytes) => bytes,
            Sha1(ref bytes, length) => &bytes[..length],
            Sha2_256(ref bytes, length) => &bytes[..length],
            Sha2_512(ref bytes, length) => &bytes[..length],
            Sha3_224(ref bytes, length) => &bytes[..length],
            Sha3_256(ref bytes, length) => &bytes[..length],
            Sha3_384(ref bytes, length) => &bytes[..length],
            Sha3_512(ref bytes, length) => &bytes[..length],
            Shake128(ref bytes) => bytes,
            Shake256(ref bytes) => bytes,
            Blake2B(ref bytes, length) => &bytes[..length],
            Blake2S(ref bytes, length) => &bytes[..length],
            ApplicationSpecific { ref bytes, .. } => bytes,
        }
    }

    /// A mutable reference to the bytes making up the digest of this multihash.
    pub fn digest_mut(&mut self) -> &mut [u8] {
        match *self {
            Identity(ref mut bytes) => bytes,
            Sha1(ref mut bytes, length) => &mut bytes[..length],
            Sha2_256(ref mut bytes, length) => &mut bytes[..length],
            Sha2_512(ref mut bytes, length) => &mut bytes[..length],
            Sha3_224(ref mut bytes, length) => &mut bytes[..length],
            Sha3_256(ref mut bytes, length) => &mut bytes[..length],
            Sha3_384(ref mut bytes, length) => &mut bytes[..length],
            Sha3_512(ref mut bytes, length) => &mut bytes[..length],
            Shake128(ref mut bytes) => bytes,
            Shake256(ref mut bytes) => bytes,
            Blake2B(ref mut bytes, length) => &mut bytes[..length],
            Blake2S(ref mut bytes, length) => &mut bytes[..length],
            ApplicationSpecific { ref mut bytes, .. } => bytes,
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
        try!(f.write_str(self.name()));
        try!(f.write_str("(\""));
        for byte in self.digest() {
            try!(write!(f, "{:x}", byte));
        }
        try!(f.write_str("\")"));
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
        match (self, other) {
            (&Identity(ref left), &Identity(ref right)) => left == right,
            (&Sha1(ref left, l1), &Sha1(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha2_256(ref left, l1), &Sha2_256(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha2_512(ref left, l1), &Sha2_512(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_224(ref left, l1), &Sha3_224(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_256(ref left, l1), &Sha3_256(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_384(ref left, l1), &Sha3_384(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_512(ref left, l1), &Sha3_512(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Shake128(ref left), &Shake128(ref right)) => left == right,
            (&Shake256(ref left), &Shake256(ref right)) => left == right,
            (&Blake2B(ref left, l1), &Blake2B(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Blake2S(ref left, l1), &Blake2S(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (
                &ApplicationSpecific { code: left_code, bytes: ref left },
                &ApplicationSpecific { code: right_code, bytes: ref right }
            ) => left_code == right_code && left == right,
            _ => false,
        }
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
            Ok(multihash),
            MultiHash::from_bytes([0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn from_bytes_with_varint() {
        let multihash = MultiHash::ApplicationSpecific {
            code: 0x0401,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(
            Ok(multihash),
            MultiHash::from_bytes([0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]));
    }
}
