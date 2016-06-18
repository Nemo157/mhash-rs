use std::io;
use std::convert::AsRef;

use { Code, MultiHash };

trait WriteHelper {
    fn write_byte(&mut self, byte: u8) -> io::Result<()>;
}

pub trait WriteMultiHash {
    fn write_multihash_code(&mut self, code: Code) -> io::Result<()>;
    fn write_multihash<D: AsRef<[u8]>>(&mut self, multihash: &MultiHash<D>) -> io::Result<()>;
}

impl<R> WriteHelper for R where R: io::Write {
    fn write_byte(&mut self, byte: u8) -> io::Result<()> {
        try!(self.write_all(&[byte]));
        Ok(())
    }
}

impl<R> WriteMultiHash for R where R: io::Write {
    fn write_multihash_code(&mut self, code: Code) -> io::Result<()> {
        try!(self.write_byte(code.to_byte()));
        Ok(())
    }

    fn write_multihash<D: AsRef<[u8]>>(&mut self, multihash: &MultiHash<D>) -> io::Result<()> {
        try!(self.write_multihash_code(multihash.code()));
        try!(self.write_byte(multihash.digest().len() as u8));
        try!(self.write_all(multihash.digest()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use { Code, MultiHash, ShaVariant, WriteMultiHash };

    #[test]
    fn valid() {
        let mut buffer = vec![];
        let multihash = MultiHash::new(
            Code::Sha(ShaVariant::Sha1),
            vec![0xde, 0xad, 0xbe, 0xef]);
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, vec![0x11u8, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }
}
