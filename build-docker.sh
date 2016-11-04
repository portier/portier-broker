#!/bin/bash
# This script builds the portier/broker Docker image. The image contains a
# static release build of portier-broker, and a bundle of root certificates
# extracted from Debian.
set -xe
cd "$(dirname "${0}")/"

SOURCE_DIR="${PWD}"
TARGET_DIR="target/x86_64-unknown-linux-musl/release"
DOCKER_SOCK="/var/run/docker.sock"

docker run --rm \
    -v "${SOURCE_DIR}":/src -w /src \
    -e CARGO_HOME="/src/${TARGET_DIR}/.cargo" \
    clux/muslrust cargo build --release

container="$(
    docker create \
        -v "${DOCKER_SOCK}":"${DOCKER_SOCK}":ro \
        -i docker /bin/sh -xes
)"
trap "docker rm -f ${container}" exit

docker cp "${TARGET_DIR}/portier-broker" "${container}:/tmp/portier-broker"
docker cp "tmpl" "${container}:/tmp/tmpl"
docker cp "res" "${container}:/tmp/res"
docker start -ai "${container}" << END_CONTAINER_SCRIPT

mkdir /tmp/build
cd /tmp/build
mv /tmp/portier-broker /tmp/tmpl /tmp/res ./

mkdir certs
cd certs
cp -L /usr/share/ca-certificates/mozilla/*.crt .
c_rehash .
cat *.crt > ca-certificates.crt
cd ..

tee Dockerfile > /dev/null << EOF
FROM scratch

COPY . /
USER 65534:65534
ENV SSL_CERT_FILE=/certs/ca-certificates.crt \
    SSL_CERT_DIR=/certs \
    BROKER_IP=::
ENTRYPOINT ["/portier-broker"]
EXPOSE 3333
EOF
docker build -t portier/broker .

END_CONTAINER_SCRIPT
