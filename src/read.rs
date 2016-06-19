use std::io;

use { Digest, MultiHash };

trait ReadHelper {
    fn read_byte(&mut self) -> io::Result<u8>;
}

pub trait ReadMultiHash {
    fn read_multihash(&mut self) -> io::Result<MultiHash>;
}

impl<R: io::Read> ReadHelper for R {
    fn read_byte(&mut self) -> io::Result<u8> {
        let mut buffer = [0];
        try!(self.read_exact(&mut buffer));
        Ok(buffer[0])
    }
}

impl<R: io::Read> ReadMultiHash for R {
    fn read_multihash(&mut self) -> io::Result<MultiHash> {
        let code = try!(self.read_byte());
        let length = try!(self.read_byte()) as usize;
        let mut digest = try!(Digest::from_code_and_length(code, length)
               .map_err(|err| io::Error::new(io::ErrorKind::Other, err)));
        try!(self.read_exact(&mut digest.mut_bytes()[..length]));

        Ok(MultiHash::new(length, digest))
    }
}

#[cfg(test)]
mod tests {
    use { Digest, MultiHash, ReadMultiHash };

    #[test]
    fn valid() {
        let digest = [
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut buffer: &[u8] = &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            MultiHash::new(4, Digest::Sha1(digest)),
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

    #[test]
    fn long_digest() {
        let mut buffer: &[u8] = &[
            0x11, 0x20,
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(buffer.read_multihash().is_err());
    }
}
