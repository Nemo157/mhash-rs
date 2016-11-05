use std::fmt::{ Display, Formatter, Result };
use std::str::FromStr;

use bs58::{ ToBase58, FromBase58 };

use error;
use MultiHash;

impl<D: AsRef<[u8]>> Display for MultiHash<D> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", self.to_bytes().to_base58())
    }
}

impl FromStr for MultiHash<Vec<u8>> {
    type Err = error::parse::Error;
    fn from_str(s: &str) -> error::parse::Result<MultiHash<Vec<u8>>> {
        Ok(try!(MultiHash::from_bytes(try!(s.from_base58()))))
    }
}

