use Code;

#[derive(Debug)]
pub struct MultiHash<D: AsRef<[u8]>> {
    code: Code,
    digest: D
}

impl<D: AsRef<[u8]>> MultiHash<D> {
    pub fn new(code: Code, digest: D) -> MultiHash<D> {
        MultiHash {
            code: code,
            digest: digest,
        }
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn digest(&self) -> &[u8] {
        self.digest.as_ref()
    }
}

impl<'a> MultiHash<&'a [u8]> {
    // TODO: Return real error
    pub fn decode(buffer: &'a [u8]) -> Result<MultiHash<&'a [u8]>, &'static str> {
        if buffer.len() < 1 { return Err("No code"); }
        if buffer.len() < 2 { return Err("No length"); }
        let code = try!(Code::from_byte(buffer[0]));
        let length = buffer[1] as usize;
        if buffer.len() != length + 2 { return Err("Wrong length") }

        Ok(MultiHash {
            code: code,
            digest: &buffer[2..]
        })
    }
}

impl<D: AsRef<[u8]>> Eq for MultiHash<D> {}
impl<D: AsRef<[u8]>> PartialEq for MultiHash<D> {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.digest().len() == other.digest().len()
            && self.digest().iter().zip(other.digest().iter()).all(|(l,r)| l == r)
    }
}

#[cfg(test)]
mod tests {
    use { Code, MultiHash, ShaVariant };

    #[test]
    fn valid() {
        let digest: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let buffer: &[u8] = &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            Ok(MultiHash::new(Code::Sha(ShaVariant::Sha1), digest)),
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
