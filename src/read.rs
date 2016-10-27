use std::io::{ Read, Error, ErrorKind };
use futures::Future;
use tokio_ext::{ read_exact, Failure, Continuation };

use { Digest, MultiHash };

pub fn read_multihash<R: Read>(reader: R) -> impl Future<Item=(R, MultiHash), Error=Error> {
    read_exact(reader, [0, 0])
        .and_then(|(reader, [code, length])| {
            let length = length as usize;
            match Digest::from_code_and_length(code, length)
               .map_err(|err| Error::new(ErrorKind::Other, err)) {
                Err(error) => Failure(error),
                Ok(digest) => Continuation(read_exact(reader, digest)
                    .map(|(reader, digest)| (reader, MultiHash::new(digest)))),
            }
        })
}

#[cfg(test)]
mod tests {
    use futures::Future;
    use { Digest, MultiHash, read_multihash };

    #[test]
    fn valid() {
        let digest = [
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let buffer: &[u8] = &[0x11, 0x04, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            MultiHash::new(Digest::Sha1(digest, 4)),
            read_multihash(buffer).wait().unwrap().1);
    }

    #[test]
    fn no_code() {
        let buffer: &[u8] = &[];
        read_multihash(buffer).wait().is_err();
    }

    #[test]
    fn no_len() {
        let buffer: &[u8] = &[0x11];
        read_multihash(buffer).wait().is_err();
    }

    #[test]
    fn bad_code() {
        let buffer: &[u8] = &[0x90, 0x04, 0xde, 0xad, 0xbe, 0xef];
        read_multihash(buffer).wait().is_err();
    }

    #[test]
    fn short_digest() {
        let buffer: &[u8] = &[0x11, 0x05, 0xde, 0xad, 0xbe, 0xef];
        read_multihash(buffer).wait().is_err();
    }

    #[test]
    fn long_digest() {
        let buffer: &[u8] = &[
            0x11, 0x20,
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        read_multihash(buffer).wait().is_err();
    }
}
