use std::str::FromStr;

use bs58::FromBase58;

use MultiHash;

pub use self::error::*;

mod error {
    use bs58;

    error_chain! {
        foreign_links {
            bs58::FromBase58Error, Base58;
        }
    }
}

impl FromStr for MultiHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<MultiHash> {
        Ok(try!(MultiHash::from_bytes(try!(s.from_base58()))))
    }
}

