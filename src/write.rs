use std::io;

use varmint::WriteVarInt;

use MultiHash;

pub trait WriteMultiHash {
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()>;
}

impl<W> WriteMultiHash for W where W: io::Write {
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()> {
        try!(self.write_usize_varint(multihash.code()));
        try!(self.write_usize_varint(multihash.len()));
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

    #[test]
    fn varint() {
        let mut buffer = vec![];
        let multihash = MultiHash::ApplicationSpecific {
            code: 0x0401,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, vec![0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }
}
