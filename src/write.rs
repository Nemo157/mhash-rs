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
        try!(self.write_byte(multihash.len() as u8));
        try!(self.write_all(multihash.digest()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use { MultiHash, WriteMultiHash };

    #[test]
    fn valid() {
        let mut buffer = vec![];
        let multihash = MultiHash::Sha1([
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ], 4);
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, vec![0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }
}
