extern crate mhash;

use std::env;
use std::str::FromStr;

use mhash::MultiHash;

fn main() {
    let s = env::args().skip(1).next().unwrap();
    println!("{:?}", MultiHash::from_str(&s));
}
