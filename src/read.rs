use std::io;

use { Code, MultiHash };

trait ReadHelper {
    fn read_byte(&mut self) -> io::Result<u8>;
}

pub trait ReadMultiHash {
    fn read_multihash_code(&mut self) -> io::Result<Code>;
    fn read_multihash(&mut self) -> io::Result<MultiHash<Vec<u8>>>;
}

impl<R: io::Read> ReadHelper for R {
    fn read_byte(&mut self) -> io::Result<u8> {
        let mut buffer = [0];
        try!(self.read_exact(&mut buffer));
        Ok(buffer[0])
    }
}

impl<R: io::Read> ReadMultiHash for R {
    fn read_multihash_code(&mut self) -> io::Result<Code> {
        Code::from_byte(try!(self.read_byte()))
           .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    fn read_multihash(&mut self) -> io::Result<MultiHash<Vec<u8>>> {
        let code = try!(self.read_multihash_code());
        let length = try!(self.read_byte()) as usize;
        let mut buffer = Vec::with_capacity(length);
        buffer.resize(length, 0);
        try!(self.read_exact(&mut buffer));

        Ok(MultiHash::new(code, buffer))
    }
}

#[cfg(test)]
mod tests {
    use { Code, MultiHash, ShaVariant, ReadMultiHash };

    #[test]
    fn valid() {
        let digest = vec![0xde, 0xad, 0xbe, 0xef];
        let mut buffer: &[u8] = &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            MultiHash::new(Code::Sha(ShaVariant::Sha1), digest),
            buffer.read_multihash().unwrap());
    }

    #[test]
    fn no_code() {
        let mut buffer: &[u8] = &[];
        assert!(buffer.read_multihash().is_err());
    }

    #[test]
    fn no_len() {
        let mut buffer: &[u8] = &[0x11];
        assert!(buffer.read_multihash().is_err());
    }

    #[test]
    fn bad_code() {
        let mut buffer: &[u8] = &[0x90, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert!(buffer.read_multihash().is_err());
    }

    #[test]
    fn short_digest() {
        let mut buffer: &[u8] = &[0x11, 0x05, 0xde, 0xad, 0xbe, 0xef];
        assert!(buffer.read_multihash().is_err());
    }
}
