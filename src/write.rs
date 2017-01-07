use std::io;

use varmint::WriteVarInt;

use MultiHash;

/// A trait to allow writing a `MultiHash` to an object.
///
/// This is primarily intended to provide support for the `io::Write` trait,
/// allowing writing a `MultiHash` to a stream without having to allocate space
/// to store the bytes.
pub trait WriteMultiHash {
    /// Write the given `MultiHash` to this object.
    ///
    /// # Errors
    ///
    /// Any errors encountered when writing to the underlying `io::Write`
    /// stream will be propagated out, if that happens an undefined amount of
    /// the `MultiHash` will have already been written to the stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mhash::{ MultiHash, MultiHashVariant, WriteMultiHash };
    /// let mut buffer = vec![];
    /// let multihash = MultiHash::new(
    ///     MultiHashVariant::Sha1,
    ///     &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    /// buffer.write_multihash(&multihash).unwrap();
    /// assert_eq!(buffer, [0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    /// ```
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()>;
}

impl<W> WriteMultiHash for W where W: io::Write {
    fn write_multihash(&mut self, multihash: &MultiHash) -> io::Result<()> {
        self.write_usize_varint(multihash.code())?;
        self.write_usize_varint(multihash.len())?;
        self.write_all(multihash.digest())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use { MultiHash, MultiHashVariant, WriteMultiHash };

    #[test]
    fn valid() {
        let multihash = MultiHash::new(
            MultiHashVariant::Sha1,
            &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        let mut buffer = vec![];
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn varint() {
        let multihash = MultiHash::new_with_code(
            0x401,
            &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        let mut buffer = vec![];
        buffer.write_multihash(&multihash).unwrap();
        assert_eq!(buffer, &[0x81, 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }
}
