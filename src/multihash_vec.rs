use varmint::{ self, ReadVarInt, WriteVarInt };

use error;
use MultiHash;

impl MultiHash<Vec<u8>> {
    /// Parse a binary encoded multihash
    pub fn from_bytes(mut bytes: Vec<u8>) -> error::from_bytes::Result<MultiHash<Vec<u8>>> {
        let (code, length) = {
            let mut reader: &mut &[u8] = &mut &*bytes;
            (try!(reader.read_usize_varint()), try!(reader.read_usize_varint()))
        };
        let offset = varmint::len_usize_varint(code) + varmint::len_usize_varint(length);
        if bytes.len() != length + offset {
            return Err(error::from_bytes::ErrorKind::WrongLengthGiven(bytes.len(), length + offset).into());
        }
        let bytes = bytes.split_off(offset);
        Ok(try!(MultiHash::new_with_code(code, bytes)))
    }
}


impl<D: AsRef<[u8]>> MultiHash<D> {
    /// Create a `Vec<u8>` with the binary encoding of this multihash.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.output_len());
        {
            let mut writer = &mut bytes;
            writer.write_usize_varint(self.code()).unwrap();
            writer.write_usize_varint(self.len()).unwrap();
        }
        bytes.extend_from_slice(self.digest());
        bytes
    }

    /// The length this multihash will use when serialized to a byte
    /// array/stream.
    pub fn output_len(&self) -> usize {
        varmint::len_usize_varint(self.code())
            + varmint::len_usize_varint(self.len())
            + self.len()
    }
}

#[cfg(test)]
mod tests {
    use { MultiHash, MultiHashVariant };

    #[test]
    fn to_bytes() {
        assert_eq!(
            MultiHash::new(MultiHashVariant::Sha1, [0xde, 0xad, 0xbe, 0xef])
                .unwrap().to_bytes(),
            vec![0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn to_bytes_with_varint() {
        assert_eq!(
            MultiHash::new_with_code(0x401, [0xde, 0xad, 0xbe, 0xef])
                .unwrap().to_bytes(),
            vec![0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            MultiHash::new(MultiHashVariant::Sha1, [0xde, 0xad, 0xbe, 0xef])
                .unwrap(),
            MultiHash::from_bytes(vec![0x11, 0x04, 0xde, 0xad, 0xbe, 0xef])
                .unwrap());
    }

    #[test]
    fn from_bytes_with_varint() {
        assert_eq!(
            MultiHash::new_with_code(0x401, [0xde, 0xad, 0xbe, 0xef])
                .unwrap(),
            MultiHash::from_bytes(vec![0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef])
                .unwrap());
    }
}
