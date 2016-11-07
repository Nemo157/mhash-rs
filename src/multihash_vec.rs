use varmint::{ self, ReadVarInt, WriteVarInt };

use error;
use MultiHash;

impl MultiHash {
    /// Parse a binary encoded multihash
    pub fn from_bytes(mut bytes: &[u8]) -> error::from_bytes::Result<MultiHash> {
        let (code, length) = (try!(bytes.read_usize_varint()), try!(bytes.read_usize_varint()));
        if bytes.len() != length {
            return Err(error::from_bytes::ErrorKind::WrongLengthGiven(bytes.len(), length).into());
        }
        Ok(try!(MultiHash::new_with_code(code, bytes)))
    }
}


impl MultiHash {
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
            MultiHash::new(MultiHashVariant::Sha1, &[0xde, 0xad, 0xbe, 0xef])
                .unwrap().to_bytes(),
            &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn to_bytes_with_varint() {
        assert_eq!(
            MultiHash::new_with_code(0x401, &[0xde, 0xad, 0xbe, 0xef])
                .unwrap().to_bytes(),
            &[0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            MultiHash::new(MultiHashVariant::Sha1, &[0xde, 0xad, 0xbe, 0xef])
                .unwrap(),
            MultiHash::from_bytes(&[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef])
                .unwrap());
    }

    #[test]
    fn from_bytes_with_varint() {
        assert_eq!(
            MultiHash::new_with_code(0x401, &[0xde, 0xad, 0xbe, 0xef])
                .unwrap(),
            MultiHash::from_bytes(&[0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef])
                .unwrap());
    }
}
