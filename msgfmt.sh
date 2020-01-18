#!/bin/bash

# Compile message catalogs to binary format.

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/lang/"

set -x
for file in *.po; do
  msgfmt "${file}" -o "${file%.po}.mo"
done
