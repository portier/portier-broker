# Private key management

The broker uses a set of private keys for signing JSON Web Tokens. By default,
these keys are managed automatically in the configured store.

When managed automatically, private keys rotate according to `keys_ttl`. In
practice, each key is valid for 3 times this duration, as the key is rotated
through three steps: next, current, previous. These three steps allow our
rotation to work well with client cache.

## Generating RSA keys

Currently, the broker is not capable of generating RSA keys by itself, and
instead an external command is invoked when a new key must be generated. By
default, this command is `openssl genrsa 2048`, but this can be customized
using the `generate_rsa_command` configuration option. This option is
documented in the [example configuration file].

[example configuration file]: ../config.toml.dist

## Import / export

The broker provides import and export options for its private keys. These can
be used to switch between stores, or switch to/from manual keying, to name some
examples.

To export private keys:

```bash
./portier-broker[.exe] --export-keys FILE
```

This command will write a series of PEM blocks to `FILE`, one for each private
key in the store.

To import private keys:

```bash
# 'Dry run' to test changes without applying them.
./portier-broker[.exe] ./config.toml --import-keys FILE --dry-run
# Import and apply changes.
./portier-broker[.exe] ./config.toml --import-keys FILE
```

This command will read a series of PEM blocks from `FILE`, parse the private
keys within, and save them in the store.

NOTE: Expiration times are currently not preserved. When importing, expiration
times are reset according to the `keys_ttl` setting.

### PEM format

If you are manually authoring a PEM file for `--import-keys`, note that the
broker applies special meaning to the order of PEM blocks in the file.

- Internally, the broker manages 'key sets', one for each kind of signing
  algorithm used. The PEM file may interleave different types of keys, and only
  the order among keys of the same type matters.

- Between 0 and 3 keys of a type are expected, in the order: current, next,
  previous. If zero of a type are present, that key set is left intact.
  Otherwise, the key set for that type is entirely replaced.

- Both PKCS#8 and unwrapped RSA DER keys are supported.

## Manual keying

If you instead wish to manually manage private keys for the broker, setting
either of `keyfiles` and `keytext` will cause the broker to use keys in those
files and disable automatic keying.

The input must contain some PEM blocks, and at least one valid private key for
each enabled signing algorithm. Both PKCS#8 and unwrapped RSA DER keys are
supported. For signing, the broker uses the last key encountered of the type
required by the signing algorithm.

If `keyfiles` and `keytext` are both used, keys in `keytext` are ordered
_after_ keys from `keyfiles`.

NOTE: Inputs are read during broker startup, and there is currently no way to
reload configuration. Rotating keys manually requires restarting the broker.

NOTE: When using manual keying, keys are served to clients with a
`Cache-Control` header and `max-age` set according to the `keys_ttl` setting.
When manually changing keys, keep in mind how long clients may be caching your
public keys. (Proxies can be ignored, because we add `s-max-age=0`.)
