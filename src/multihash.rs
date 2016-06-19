use std::borrow::Cow;

use Code;

#[cfg(all(feature = "validation", feature = "validation-sha2"))]
use validation::Validator;

#[cfg(all(feature = "validation", feature = "validation-sha2"))]
use validation::sha2::{Sha256Validator,Sha512Validator};

#[derive(Debug)]
pub struct MultiHash<'a> {
    code: Code,
    digest: Cow<'a, [u8]>,
}

impl<'a> MultiHash<'a> {
    pub fn new(code: Code, digest: Cow<'a, [u8]>) -> MultiHash<'a> {
        MultiHash {
            code: code,
            digest: digest,
        }
    }

    // TODO: Return real error
    pub fn decode(buffer: &[u8]) -> Result<MultiHash, &'static str> {
        if buffer.len() < 1 { return Err("No code"); }
        if buffer.len() < 2 { return Err("No length"); }
        let code = try!(Code::from_byte(buffer[0]));
        let length = buffer[1] as usize;
        if buffer.len() != length + 2 { return Err("Wrong length") }

        Ok(MultiHash {
            code: code,
            digest: Cow::Borrowed(&buffer[2..]),
        })
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn digest(&self) -> &[u8] {
        &*self.digest
    }

    /// The length of this multihash when writing to a byte stream
    pub fn len(&self) -> usize {
        self.digest.len() + 2
    }

    #[cfg(all(feature = "validation", feature = "validation-sha2"))]
    pub fn validate(&self, data: &[u8]) -> Result<bool, Cow<'static, str>> {
        if self.code.to_byte() == 0x12 {
            Sha256Validator.validate(self.digest.as_ref(), data)
        } else if self.code.to_byte() == 0x13 {
            Sha512Validator.validate(self.digest.as_ref(), data)
        } else {
            Err("Unknown code".into())
        }
    }
}

impl<'a> Eq for MultiHash<'a> {}
impl<'a> PartialEq for MultiHash<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.digest().len() == other.digest().len()
            && self.digest().iter().zip(other.digest().iter()).all(|(l,r)| l == r)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use { Code, MultiHash, ShaVariant };

    #[test]
    fn valid() {
        let digest: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let buffer: &[u8] = &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            Ok(MultiHash::new(Code::Sha(ShaVariant::Sha1), Cow::Borrowed(digest))),
            MultiHash::decode(buffer));
    }

    #[test]
    fn no_code() {
        let buffer: &[u8] = &[];
        assert!(MultiHash::decode(buffer).is_err());
    }

    #[test]
    fn no_len() {
        let buffer: &[u8] = &[0x11];
        assert!(MultiHash::decode(buffer).is_err());
    }

    #[test]
    fn bad_code() {
        let buffer: &[u8] = &[0x90, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert!(MultiHash::decode(buffer).is_err());
    }

    #[test]
    fn short_digest() {
        let buffer: &[u8] = &[0x11, 0x05, 0xde, 0xad, 0xbe, 0xef];
        assert!(MultiHash::decode(buffer).is_err());
    }

    #[test]
    fn long_digest() {
        let buffer: &[u8] = &[0x11, 0x03, 0xde, 0xad, 0xbe, 0xef];
        assert!(MultiHash::decode(buffer).is_err());
    }
}
