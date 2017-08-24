use url::Url;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};


/// Type which can be used to serialize a Url.
///
/// `#[serde(with = "UrlDef")]`
pub struct UrlDef(Url);

impl UrlDef {
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
            where D: Deserializer<'de> {
        <&str>::deserialize(deserializer).and_then(|s| {
            s.parse().map_err(|e| DeserializeError::custom(format!("invalid URL: {}", e)))
        })
    }

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
        url.as_str().serialize(serializer)
    }
}

impl From<UrlDef> for Url {
    fn from(def: UrlDef) -> Url {
        def.0
    }
}
