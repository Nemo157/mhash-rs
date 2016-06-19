#[cfg(feature = "validation_sha2")]
pub mod sha2;

use std::borrow::Cow;
use std::sync::Mutex;

pub trait Validator: Sync {
    // TODO: Real error
    fn validate(&self, digest: &[u8], data: &[u8]) -> Result<bool, Cow<'static, str>>;
}

pub struct Validators {
    store: Mutex<[Option<&'static Validator>; 0x7F]>,
}

impl Validators {
    pub fn register(&self, code: u8, validator: &'static Validator) {
        self.store.lock().unwrap()[code as usize] = Some(validator);
    }

    pub fn get(&self, code: u8) -> Option<&'static Validator> {
        self.store.lock().unwrap()[code as usize]
    }
}

#[cfg(not(feature = "validation_sha2"))]
lazy_static! {
    pub static ref VALIDATORS: Validators = Validators { store: Mutex::new([None; 0x7F]) };
}

#[cfg(feature = "validation_sha2")]
lazy_static! {
    pub static ref VALIDATORS: Validators = {
        let validators = Validators { store: Mutex::new([None; 0x7F]) };
        {
            validators.register(0x12, &sha2::SHA256_VALIDATOR);
            validators.register(0x13, &sha2::SHA512_VALIDATOR);
        }
        validators
    };
}
