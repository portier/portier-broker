/// Macro used to extract a parameter from a `QueryMap`.
///
/// Will return from the caller with a `BrokerError` if
/// the parameter is missing and has no default.
///
/// ```
/// let foo = try_get_param!(ctx, "foo");
/// let foo = try_get_param!(ctx, "foo", "default");
/// ```
#[macro_export]
macro_rules! try_get_param {
    ( $ctx:expr , $key:tt ) => {
        match $ctx.params.remove($key) {
            Some(value) => value,
            None => return Box::new(future::err(BrokerError::Input(
                concat!("missing request parameter ", $key).to_owned()))),
        }
    };
    ( $ctx:expr , $key:tt , $default:expr ) => {
        $ctx.params.remove($key).unwrap_or($default)
    };
}


/// Macro used to extract a typed field from a JSON Value.
///
/// Will return from the caller with a `BrokerError` if the field is missing or its value is an
/// incompatible type. `descr` is used to format the error message.
///
/// ```
/// let foo = try_get_json_field!(value, "foo", "example document");
/// ```
macro_rules! try_get_json_field {
    ( $input:expr, $key:tt, $conv:expr, $descr:expr ) => {
        match $input.get($key).and_then($conv) {
            Some(v) => v,
            None => return future::err(BrokerError::Provider(
                format!("{} missing from {}", $key, $descr))),
        }
    };
    ( $input:expr, $key:tt, $descr:expr ) => {
        try_get_json_field!($input, $key,
            |v| v.as_str().map(|s| s.to_owned()), $descr)
    };
}


/// Macro used to verify a token payload field.
///
/// Will return from the caller with a `BrokerError` if the check fails. The `$key` and `$descr`
/// parameters are used in the error description.
///
/// ```
/// check_field!(foo == "bar", "foo", "example document");
/// ```
macro_rules! check_field {
    ( $check:expr, $key:expr, $descr:expr ) => {
        if !$check {
            return future::err(BrokerError::Provider(
                format!("{} has incorrect value in {}", $key, $descr)));
        }
    }
}
