FROM clux/muslrust:stable as builder

# Install gettext, needed to build translations
RUN set -x \
 && apt-get -y update \
 && apt-get -y install gettext

# Build the broker
COPY . /src
RUN set -x \
 && cd /src \
 && cargo build --release

# Create a certificate bundle
RUN set -x \
 && mkdir /certs \
 && cp -L /usr/share/ca-certificates/mozilla/*.crt /certs \
 && c_rehash /certs \
 && cat /certs/*.crt > /certs/ca-certificates.crt

# Create the root for the minimal image
RUN set -x \
 && mkdir -p /out/lang \
 && cp -r \
      /src/target/*/release/portier-broker \
      /src/res \
      /src/tmpl \
      /certs \
      /out \
 && cp /src/lang/*.mo /out/lang/

# Create the minimal image
FROM scratch
COPY --from=builder /out /

# Set image settings
USER 65534:65534
ENV SSL_CERT_FILE=/certs/ca-certificates.crt \
    SSL_CERT_DIR=/certs \
    BROKER_IP=::
ENTRYPOINT ["/portier-broker"]
EXPOSE 3333
