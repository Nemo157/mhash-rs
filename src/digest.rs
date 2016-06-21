use std::fmt;

use Digest::*;

#[allow(non_camel_case_types)]
pub enum Digest {
    Sha1([u8; 20]),
    Sha2_256([u8; 32]),
    Sha2_512([u8; 64]),
    Sha3_512([u8; 64]),
    Sha3_384([u8; 48]),
    Sha3_256([u8; 32]),
    Sha3_224([u8; 28]),
    Shake128([u8; 16]),
    Shake256([u8; 32]),
    Blake2B([u8; 64]),
    Blake2S([u8; 32]),
    ApplicationSpecific {
        code: u8,
        bytes: Vec<u8>,
    },
}

impl Digest {
    // TODO: Real error type
    /// Returns an empty digest of the specified type, validates code and length
    pub fn from_code_and_length(code: u8, length: usize) -> Result<Digest, &'static str> {
        match code {
            0x11 if length <= 20 => Ok(Sha1([0; 20])),
            0x12 if length <= 32 => Ok(Sha2_256([0; 32])),
            0x13 if length <= 64 => Ok(Sha2_512([0; 64])),
            0x14 if length <= 64 => Ok(Sha3_512([0; 64])),
            0x15 if length <= 48 => Ok(Sha3_384([0; 48])),
            0x16 if length <= 32 => Ok(Sha3_256([0; 32])),
            0x17 if length <= 28 => Ok(Sha3_224([0; 28])),
            0x18 if length <= 16 => Ok(Shake128([0; 16])),
            0x19 if length <= 32 => Ok(Shake256([0; 32])),

            0x40 if length <= 64 => Ok(Blake2B([0; 64])),
            0x41 if length <= 32 => Ok(Blake2S([0; 32])),

            _ if code < 0x10 && length < 0x7f =>
                Ok(ApplicationSpecific { code: code, bytes: vec![0; length] }),
            _ if code > 0x7f => Err("Codes greater than 0x7f are an unsupported future feature"),
            _ => Err("Digest length exceeds allowed length for specified type"),
        }
    }

    pub fn code(&self) -> u8 {
        match *self {
            Sha1(_) => 0x11,
            Sha2_256(_) => 0x12,
            Sha2_512(_) => 0x13,
            Sha3_512(_) => 0x14,
            Sha3_384(_) => 0x15,
            Sha3_256(_) => 0x16,
            Sha3_224(_) => 0x17,
            Shake128(_) => 0x18,
            Shake256(_) => 0x19,
            Blake2B(_) => 0x40,
            Blake2S(_) => 0x41,

            ApplicationSpecific { code, .. } if code < 0x10 => code,

            // TODO: could just ignore them being invalid or return Error...
            ApplicationSpecific { code, .. } =>
                panic!("application specific code {:#02x} outside allowed range 0x00-0x0f", code),
        }
    }

    pub fn name(&self) -> &'static str {
        match *self {
            Sha1(_) => "sha1",
            Sha2_256(_) => "sha2-256",
            Sha2_512(_) => "sha2-512",
            Sha3_224(_) => "sha3-224",
            Sha3_256(_) => "sha3-256",
            Sha3_384(_) => "sha3-384",
            Sha3_512(_) => "sha3-512",
            Shake128(_) => "shake-128",
            Shake256(_) => "shake-256",
            Blake2B(_) => "blake2b",
            Blake2S(_) => "blake2s",

            ApplicationSpecific { code, .. } if code < 0x10 => "app-specific",
            _ => panic!("TODO: not panic"),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match *self {
            Sha1(ref bytes) => bytes,
            Sha2_256(ref bytes) => bytes,
            Sha2_512(ref bytes) => bytes,
            Sha3_224(ref bytes) => bytes,
            Sha3_256(ref bytes) => bytes,
            Sha3_384(ref bytes) => bytes,
            Sha3_512(ref bytes) => bytes,
            Shake128(ref bytes) => bytes,
            Shake256(ref bytes) => bytes,
            Blake2B(ref bytes) => bytes,
            Blake2S(ref bytes) => bytes,
            ApplicationSpecific { ref bytes, .. } => bytes,
        }
    }

    pub fn mut_bytes(&mut self) -> &mut [u8] {
        match *self {
            Sha1(ref mut bytes) => bytes,
            Sha2_256(ref mut bytes) => bytes,
            Sha2_512(ref mut bytes) => bytes,
            Sha3_224(ref mut bytes) => bytes,
            Sha3_256(ref mut bytes) => bytes,
            Sha3_384(ref mut bytes) => bytes,
            Sha3_512(ref mut bytes) => bytes,
            Shake128(ref mut bytes) => bytes,
            Shake256(ref mut bytes) => bytes,
            Blake2B(ref mut bytes) => bytes,
            Blake2S(ref mut bytes) => bytes,
            ApplicationSpecific { ref mut bytes, .. } => bytes,
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple(self.name()).field(&self.bytes().to_vec()).finish()
    }
}

impl Clone for Digest {
    fn clone(&self) -> Digest {
        match *self {
            Sha1(ref bytes) => Sha1(*bytes),
            Sha2_256(ref bytes) => Sha2_256(*bytes),
            Sha2_512(ref bytes) => Sha2_512(*bytes),
            Sha3_224(ref bytes) => Sha3_224(*bytes),
            Sha3_256(ref bytes) => Sha3_256(*bytes),
            Sha3_384(ref bytes) => Sha3_384(*bytes),
            Sha3_512(ref bytes) => Sha3_512(*bytes),
            Shake128(ref bytes) => Shake128(*bytes),
            Shake256(ref bytes) => Shake256(*bytes),
            Blake2B(ref bytes) => Blake2B(*bytes),
            Blake2S(ref bytes) => Blake2S(*bytes),
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
            (&Sha1(ref left), &Sha1(ref right)) => left == right,
            (&Sha2_256(ref left), &Sha2_256(ref right)) => left == right,
            (&Sha2_512(ref left), &Sha2_512(ref right)) => left[..] == right[..],
            (&Sha3_224(ref left), &Sha3_224(ref right)) => left == right,
            (&Sha3_256(ref left), &Sha3_256(ref right)) => left == right,
            (&Sha3_384(ref left), &Sha3_384(ref right)) => left[..] == right[..],
            (&Sha3_512(ref left), &Sha3_512(ref right)) => left[..] == right[..],
            (&Shake128(ref left), &Shake128(ref right)) => left == right,
            (&Shake256(ref left), &Shake256(ref right)) => left == right,
            (&Blake2B(ref left), &Blake2B(ref right)) => left[..] == right[..],
            (&Blake2S(ref left), &Blake2S(ref right)) => left == right,
            (
                &ApplicationSpecific { code: left_code, bytes: ref left },
                &ApplicationSpecific { code: right_code, bytes: ref right }
            ) if left_code == right_code => left == right,
            _ => false,
        }
    }
}
