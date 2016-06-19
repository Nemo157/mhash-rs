use std::io;

use { MultiHash };

trait WriteHelper {
    fn write_byte(&mut self, byte: u8) -> io::Result<()>;
}

pub trait WriteMultiHash {
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()>;
}

impl<R> WriteHelper for R where R: io::Write {
    fn write_byte(&mut self, byte: u8) -> io::Result<()> {
        try!(self.write_all(&[byte]));
        Ok(())
    }
}

impl<R> WriteMultiHash for R where R: io::Write {
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()> {
        try!(self.write_byte(multihash.code()));
        try!(self.write_byte(multihash.digest_length() as u8));
        try!(self.write_all(multihash.digest_bytes()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use { MultiHash, Digest, WriteMultiHash };

    #[test]
    fn valid() {
        let mut buffer = vec![];
        let multihash = MultiHash::new(4, Digest::Sha1([
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]));
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, vec![0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }
}
