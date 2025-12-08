/// Macro used to extract a parameter from a `QueryMap`.
///
/// Will return from the caller with a `BrokerError::Input` if
/// the parameter is missing and has no default.
///
/// ```
/// let foo = try_get_input_param!(params, "foo");
/// let foo = try_get_input_param!(params, "foo", "default");
/// ```
#[macro_export]
macro_rules! try_get_input_param {
    ( $params:expr, $key:tt ) => {
        $params.remove($key).ok_or_else(|| {
            $crate::error::BrokerError::Input(
                concat!("missing request parameter ", $key).to_owned(),
            )
        })?
    };
    ( $params:expr, $key:tt, $default:expr ) => {
        $params.remove($key).unwrap_or($default)
    };
}

/// Macro used to extract a parameter from a `QueryMap`.
///
/// Will return from the caller with a `BrokerError::ProviderInput` if
/// the parameter is missing.
///
/// ```
/// let foo = try_get_provider_param!(params, "foo");
/// ```
#[macro_export]
macro_rules! try_get_provider_param {
    ( $params:expr, $key:tt ) => {
        $params.remove($key).ok_or_else(|| {
            $crate::error::BrokerError::ProviderInput(
                concat!("missing request parameter ", $key).to_owned(),
            )
        })?
    };
}

/// Macro used to extract a typed field from a JSON Value.
///
/// Will return from the caller with a `BrokerError` if the field is missing or its value is an
/// incompatible type. `descr` is used to format the error message.
///
/// ```
/// let foo = try_get_token_field!(value, "foo", "example document");
/// ```
macro_rules! try_get_token_field {
    ( $input:expr, $key:tt, $conv:expr, $descr:expr ) => {
        $input.get($key).and_then($conv).ok_or_else(|| {
            crate::error::BrokerError::ProviderInput(format!("{} missing from {}", $key, $descr))
        })?
    };
    ( $input:expr, $key:tt, $descr:expr ) => {
        try_get_token_field!($input, $key, serde_json::Value::as_str, $descr)
    };
}

/// Macro used to verify a token payload field.
///
/// Will return from the caller with a `BrokerError` if the check fails. The `$key` and `$descr`
/// parameters are used in the error description.
///
/// ```
/// check_token_field!(foo == "bar", "foo", "example document");
/// ```
macro_rules! check_token_field {
    ( $check:expr, $key:expr, $descr:expr ) => {
        if !$check {
            return Err(crate::error::BrokerError::ProviderInput(format!(
                "{} has incorrect value in {}",
                $key, $descr
            )));
        }
    };
}

/// Implements `Serialize` for a type that is `Display`.
#[macro_export]
macro_rules! serde_display {
    ( $type:ty ) => {
        impl serde::Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
    };
}

/// Implements `Deserialize` for a type that is `FromStr`.
#[macro_export]
macro_rules! serde_from_str {
    ( $type:ty ) => {
        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <String as serde::Deserialize>::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
