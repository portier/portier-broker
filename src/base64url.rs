#[inline]
pub fn encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

#[inline]
pub fn decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, ()> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD).map_err(|_| ())
}
