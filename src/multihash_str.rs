use std::fmt::{ Display, Formatter, Result };
use std::str::FromStr;

use bs58;

use error;
use MultiHash;

impl Display for MultiHash {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", bs58::encode(self.to_bytes()).into_string())
    }
}

impl FromStr for MultiHash {
    type Err = error::parse::Error;
    fn from_str(s: &str) -> error::parse::Result<MultiHash> {
        Ok(MultiHash::from_bytes(&bs58::decode(s).into_vec()?)?)
    }
}

