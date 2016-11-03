use std::io;

use varmint::ReadVarInt;

use { MultiHash };

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
        let code = self.read_usize_varint()?;
        let length = self.read_usize_varint()?;
        let mut hash = try!(MultiHash::from_code_and_length(code, length)
               .map_err(|err| io::Error::new(io::ErrorKind::Other, err)));
        try!(self.read_exact(&mut hash.digest_mut()[..length]));

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use { MultiHash, ReadMultiHash };

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
            MultiHash::Sha1(digest, 4),
            buffer.read_multihash().unwrap());
    }

    #[test]
    fn valid_varint() {
        let mut buffer: &[u8] = &[0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            MultiHash::ApplicationSpecific {
                code: 0x0401,
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
            },
            buffer.read_multihash().unwrap());
    }

    #[test]
    fn no_code() {
        let mut buffer: &[u8] = &[];
        buffer.read_multihash().is_err();
    }

    #[test]
    fn no_len() {
        let mut buffer: &[u8] = &[0x11];
        buffer.read_multihash().is_err();
    }

    #[test]
    fn bad_code() {
        let mut buffer: &[u8] = &[0x01, 0x04, 0xde, 0xad, 0xbe, 0xef];
        buffer.read_multihash().is_err();
    }

    #[test]
    fn short_digest() {
        let mut buffer: &[u8] = &[0x11, 0x05, 0xde, 0xad, 0xbe, 0xef];
        buffer.read_multihash().is_err();
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
        buffer.read_multihash().is_err();
    }
}
