use std::str::FromStr;

use bs58::FromBase58;

use error;
use MultiHash;

impl FromStr for MultiHash {
    type Err = error::parse::Error;

    fn from_str(s: &str) -> error::parse::Result<MultiHash> {
        Ok(MultiHash::from_bytes(s.from_base58()?)?)
    }
}

