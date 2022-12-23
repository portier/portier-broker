use base64::{
    alphabet,
    engine::fast_portable::{self, FastPortable},
};

pub const ENGINE: FastPortable = FastPortable::from(&alphabet::URL_SAFE, fast_portable::NO_PAD);

#[inline]
pub fn encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    base64::encode_engine(data, &ENGINE)
}

#[inline]
pub fn decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_engine(data, &ENGINE)
}
