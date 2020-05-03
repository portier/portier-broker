#!/bin/sh

# A dummy sendmail executable for testing.
# The output is parsed in `broker.js`.

echo '-----BEGIN RAW EMAIL-----' >&2
cat >&2
echo '-----END RAW EMAIL-----' >&2
