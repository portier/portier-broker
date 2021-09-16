#!/bin/bash

# Runs Scour on SVGs to create smaller versions.
# https://github.com/scour-project/scour

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

for svg in res/static/*.svg; do
  if [[ "${svg}" == *.min.svg ]]; then
    continue
  fi

  scour -i "${svg}" -o "${svg/.svg/.min.svg}" \
    --enable-viewboxing \
    --enable-id-stripping \
    --enable-comment-stripping \
    --shorten-ids \
    --indent=none
done
