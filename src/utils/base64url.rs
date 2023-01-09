use base64::prelude::*;

#[inline]
pub fn encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

#[inline]
pub fn decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_SAFE_NO_PAD.decode(data)
}
