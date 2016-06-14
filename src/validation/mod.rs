#[cfg(feature = "validation_sha2")]
pub mod sha2;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;

use Code;

pub trait Validator: Sync {
    // TODO: Real error
    fn validate(&self, digest: &[u8], data: &[u8]) -> Result<bool, Cow<'static, str>>;
}

pub struct Validators {
    store: Mutex<HashMap<Code, &'static Validator>>,
}

impl Validators {
    pub fn register(&self, code: Code, validator: &'static Validator) {
        self.store.lock().unwrap().insert(code, validator);
    }

    pub fn get(&self, code: Code) -> Option<&'static Validator> {
        self.store.lock().unwrap().get(&code).map(|&a|a)
    }
}

#[cfg(not(feature = "validation_sha2"))]
lazy_static! {
    pub static ref VALIDATORS: Validators = Validators { store: Mutex::new(HashMap::new()) };
}

#[cfg(feature = "validation_sha2")]
lazy_static! {
    pub static ref VALIDATORS: Validators = {
        let validators = Validators { store: Mutex::new(HashMap::new()) };
        {
            use code::{ ShaVariant, BlockSize };
            validators.register(Code::Sha(ShaVariant::Sha2(BlockSize::S256)), &sha2::SHA256_VALIDATOR);
            validators.register(Code::Sha(ShaVariant::Sha2(BlockSize::S512)), &sha2::SHA512_VALIDATOR);
        }
        validators
    };
}
