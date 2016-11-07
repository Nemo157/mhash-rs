use std::fmt::{ Display, Formatter, Result };
use std::str::FromStr;

use bs58::{ ToBase58, FromBase58 };

use error;
use MultiHash;

impl Display for MultiHash {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", self.to_bytes().to_base58())
    }
}

impl FromStr for MultiHash {
    type Err = error::parse::Error;
    fn from_str(s: &str) -> error::parse::Result<MultiHash> {
        Ok(try!(MultiHash::from_bytes(&try!(s.from_base58()))))
    }
}

