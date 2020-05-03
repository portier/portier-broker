#!/bin/sh

# A dummy sendmail executable for testing.
# The output is parsed in `broker.js`.

echo '-----BEGIN SENDMAIL INPUT-----' >&2
cat >&2
echo '-----END SENDMAIL INPUT-----' >&2
