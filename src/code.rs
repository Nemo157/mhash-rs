use std::borrow::Cow;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum BlockSize {
    S128,
    S224,
    S256,
    S384,
    S512,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ShaVariant {
    Sha1,
    Sha2(BlockSize),
    Sha3(BlockSize),
    Shake(BlockSize),
    UnknownSha(u8),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Blake2Variant {
    B,
    S
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Code {
    Sha(ShaVariant),
    Blake2(Blake2Variant),
    ApplicationSpecific(u8),
    Unknown(u8),
}

use BlockSize::*;
use ShaVariant::*;
use Blake2Variant::*;
use Code::*;

impl Code {
    // TODO: Return real error
    pub fn from_byte(byte: u8) -> Result<Code, &'static str> {
        match byte {
            0x11 => Ok(Sha(Sha1)),
            0x12 => Ok(Sha(Sha2(S256))),
            0x13 => Ok(Sha(Sha2(S512))),
            0x14 => Ok(Sha(Sha3(S512))),
            0x15 => Ok(Sha(Sha3(S384))),
            0x16 => Ok(Sha(Sha3(S256))),
            0x17 => Ok(Sha(Sha3(S224))),
            0x18 => Ok(Sha(Shake(S128))),
            0x19 => Ok(Sha(Shake(S256))),

            0x40 => Ok(Blake2(B)),
            0x41 => Ok(Blake2(S)),

            code if code < 0x0f => Ok(ApplicationSpecific(code)),
            code if code < 0x3f => Ok(Sha(UnknownSha(code))),
            code if code < 0x7f => Ok(Unknown(code)),
            _ => Err("Codes greater than 0x7f are an unsupported future feature"),
        }
    }

    pub fn to_byte(&self) -> u8 {
        match *self {
            Sha(Sha1) => 0x11,
            Sha(Sha2(S256)) => 0x12,
            Sha(Sha2(S512)) => 0x13,
            Sha(Sha3(S512)) => 0x14,
            Sha(Sha3(S384)) => 0x15,
            Sha(Sha3(S256)) => 0x16,
            Sha(Sha3(S224)) => 0x17,
            Sha(Shake(S128)) => 0x18,
            Sha(Shake(S256)) => 0x19,
            Blake2(B) => 0x40,
            Blake2(S) => 0x41,

            Sha(UnknownSha(code)) if code > 0x0f && code < 0x4f => code,
            ApplicationSpecific(code) if code < 0x10 => code,
            Unknown(code) if code > 0x3f && code < 0x80 => code,

            // TODO: could just ignore them being invalid or return Error...
            ApplicationSpecific(code) => panic!("application specific code {:#02x} outside allowed range 0x00-0x0f", code),
            Sha(UnknownSha(code)) => panic!("unknown sha code {:#02x} outside allowed range 0x10-0x3f", code),
            Unknown(code) => panic!("unknown code {:#02x} outside allowed range 0x40-0x7f", code),
            Sha(variant) => panic!("unsupported sha variant {:?}", variant),
        }
    }

    pub fn to_string(&self) -> Cow<'static, str> {
        match *self {
            Sha(Sha1) => "sha1".into(),
            Sha(Sha2(S256)) => "sha2-256".into(),
            Sha(Sha2(S512)) => "sha2-512".into(),
            Sha(Sha3(S224)) => "sha3-224".into(),
            Sha(Sha3(S256)) => "sha3-256".into(),
            Sha(Sha3(S384)) => "sha3-384".into(),
            Sha(Sha3(S512)) => "sha3-512".into(),
            Sha(Shake(S128)) => "shake-128".into(),
            Sha(Shake(S256)) => "shake-256".into(),
            Blake2(B) => "blake2b".into(),
            Blake2(S) => "blake2s".into(),

            Sha(UnknownSha(code)) if code > 0x0f && code < 0x4f
                => format!("unknown SHA standard function {:#02x}", code).into(),
            ApplicationSpecific(code) if code < 0x10
                => format!("application specific function {:#02x}", code).into(),
            Unknown(code) if code > 0x3f && code < 0x80
                => format!("unknown {:#02x}", code).into(),

            // TODO: could just ignore them being invalid or return Error...
            ApplicationSpecific(code) => panic!("application specific code {:#02x} outside allowed range 0x00-0x0f", code),
            Sha(UnknownSha(code)) => panic!("unknown sha code {:#02x} outside allowed range 0x10-0x3f", code),
            Unknown(code) => panic!("unknown code {:#02x} outside allowed range 0x40-0x7f", code),
            Sha(variant) => panic!("unsupported sha variant {:?}", variant),
        }
    }
}
