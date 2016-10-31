use std::fmt::{ Display, Formatter, Result };

use base58::ToBase58;

use MultiHash;

impl Display for MultiHash {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", self.to_bytes().to_base58())
    }
}
