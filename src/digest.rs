use std::fmt;

use Digest::*;

#[allow(non_camel_case_types)]
pub enum Digest {
    Sha1([u8; 20], usize),
    Sha2_256([u8; 32], usize),
    Sha2_512([u8; 64], usize),
    Sha3_512([u8; 64], usize),
    Sha3_384([u8; 48], usize),
    Sha3_256([u8; 32], usize),
    Sha3_224([u8; 28], usize),
    Shake128([u8; 16], usize),
    Shake256([u8; 32], usize),
    Blake2B([u8; 64], usize),
    Blake2S([u8; 32], usize),
    ApplicationSpecific {
        code: u8,
        bytes: Vec<u8>,
    },
}

impl Digest {
    // TODO: Real error type
    /// Returns an empty digest of the specified type, validates code and length
    pub fn from_code_and_length(code: u8, length: usize) -> Result<Digest, &'static str> {
        Ok(match code {
            0x11 if length <= 20 => Sha1([0; 20], length),
            0x12 if length <= 32 => Sha2_256([0; 32], length),
            0x13 if length <= 64 => Sha2_512([0; 64], length),
            0x14 if length <= 64 => Sha3_512([0; 64], length),
            0x15 if length <= 48 => Sha3_384([0; 48], length),
            0x16 if length <= 32 => Sha3_256([0; 32], length),
            0x17 if length <= 28 => Sha3_224([0; 28], length),
            0x18 if length <= 16 => Shake128([0; 16], length),
            0x19 if length <= 32 => Shake256([0; 32], length),

            0x40 if length <= 64 => Blake2B([0; 64], length),
            0x41 if length <= 32 => Blake2S([0; 32], length),

            _ if code < 0x10 && length < 0x7f =>
                ApplicationSpecific { code: code, bytes: vec![0; length] },
            _ if code > 0x7f => {
                return Err("Codes greater than 0x7f are an unsupported future feature")
            }
            _ => {
                return Err("Digest length exceeds allowed length for specified type")
            }
        })
    }

    pub fn len(&self) -> usize {
        match *self {
            Sha1(_, length) => length,
            Sha2_256(_, length) => length,
            Sha2_512(_, length) => length,
            Sha3_224(_, length) => length,
            Sha3_256(_, length) => length,
            Sha3_384(_, length) => length,
            Sha3_512(_, length) => length,
            Shake128(_, length) => length,
            Shake256(_, length) => length,
            Blake2B(_, length) => length,
            Blake2S(_, length) => length,
            ApplicationSpecific { ref bytes, .. } => bytes.len(),
        }
    }

    pub fn code(&self) -> u8 {
        match *self {
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

            ApplicationSpecific { code, .. } if code < 0x10 => code,

            // TODO: could just ignore them being invalid or return Error...
            ApplicationSpecific { code, .. } =>
                panic!("application specific code {:#02x} outside allowed range 0x00-0x0f", code),
        }
    }

    pub fn name(&self) -> &'static str {
        match *self {
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

            ApplicationSpecific { code, .. } if code < 0x10 => "app-specific",
            _ => panic!("TODO: not panic"),
        }
    }
}


impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Sha1(ref bytes, length) => &bytes[..length],
            Sha2_256(ref bytes, length) => &bytes[..length],
            Sha2_512(ref bytes, length) => &bytes[..length],
            Sha3_224(ref bytes, length) => &bytes[..length],
            Sha3_256(ref bytes, length) => &bytes[..length],
            Sha3_384(ref bytes, length) => &bytes[..length],
            Sha3_512(ref bytes, length) => &bytes[..length],
            Shake128(ref bytes, length) => &bytes[..length],
            Shake256(ref bytes, length) => &bytes[..length],
            Blake2B(ref bytes, length) => &bytes[..length],
            Blake2S(ref bytes, length) => &bytes[..length],
            ApplicationSpecific { ref bytes, .. } => bytes,
        }
    }
}

impl AsMut<[u8]> for Digest {
    fn as_mut(&mut self) -> &mut [u8] {
        match *self {
            Sha1(ref mut bytes, length) => &mut bytes[..length],
            Sha2_256(ref mut bytes, length) => &mut bytes[..length],
            Sha2_512(ref mut bytes, length) => &mut bytes[..length],
            Sha3_224(ref mut bytes, length) => &mut bytes[..length],
            Sha3_256(ref mut bytes, length) => &mut bytes[..length],
            Sha3_384(ref mut bytes, length) => &mut bytes[..length],
            Sha3_512(ref mut bytes, length) => &mut bytes[..length],
            Shake128(ref mut bytes, length) => &mut bytes[..length],
            Shake256(ref mut bytes, length) => &mut bytes[..length],
            Blake2B(ref mut bytes, length) => &mut bytes[..length],
            Blake2S(ref mut bytes, length) => &mut bytes[..length],
            ApplicationSpecific { ref mut bytes, .. } => bytes,
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str(self.name()));
        try!(f.write_str("(\""));
        for byte in self.as_ref() {
            try!(write!(f, "{:x}", byte));
        }
        try!(f.write_str("\")"));
        Ok(())
    }
}

impl Clone for Digest {
    fn clone(&self) -> Digest {
        match *self {
            Sha1(ref bytes, length) => Sha1(*bytes, length),
            Sha2_256(ref bytes, length) => Sha2_256(*bytes, length),
            Sha2_512(ref bytes, length) => Sha2_512(*bytes, length),
            Sha3_224(ref bytes, length) => Sha3_224(*bytes, length),
            Sha3_256(ref bytes, length) => Sha3_256(*bytes, length),
            Sha3_384(ref bytes, length) => Sha3_384(*bytes, length),
            Sha3_512(ref bytes, length) => Sha3_512(*bytes, length),
            Shake128(ref bytes, length) => Shake128(*bytes, length),
            Shake256(ref bytes, length) => Shake256(*bytes, length),
            Blake2B(ref bytes, length) => Blake2B(*bytes, length),
            Blake2S(ref bytes, length) => Blake2S(*bytes, length),
            ApplicationSpecific { code, ref bytes } => ApplicationSpecific {
                code: code,
                bytes: bytes.clone(),
            },
        }
    }
}

impl Eq for Digest {}
impl PartialEq for Digest {
    fn eq(&self, other: &Digest) -> bool {
        match (self, other) {
            (&Sha1(ref left, l1), &Sha1(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha2_256(ref left, l1), &Sha2_256(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha2_512(ref left, l1), &Sha2_512(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_224(ref left, l1), &Sha3_224(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_256(ref left, l1), &Sha3_256(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_384(ref left, l1), &Sha3_384(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Sha3_512(ref left, l1), &Sha3_512(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Shake128(ref left, l1), &Shake128(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
            (&Shake256(ref left, l1), &Shake256(ref right, l2)) => l1 == l2 && left[..l1] == right[..l2],
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