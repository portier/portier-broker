# This Dockerfile creates an image with a release build of the broker.
#
# To run a container:
#
#   docker run -v /srv/portier-broker:/data:ro portier/broker /data/config.toml
#

# Create a release build.
FROM rust:1-buster as build
WORKDIR /src
COPY . .
RUN cargo build --release

# Prepare a 'package' directory with the exact files we want.
RUN set -x \
  && mkdir package \
  && cp -R \
    lang \
    res \
    tmpl \
    target/release/portier-broker \
    package/ \
  && rm lang/*.po

# Prepare a final image from a plain Debian base.
FROM debian:buster

# Add a user and group first to make sure their IDs get assigned consistently,
# regardless of whatever dependencies get added.
RUN set -x \
  && groupadd -r -g 999 portier-broker \
  && useradd -r -g portier-broker -u 999 portier-broker

# Install run-time dependencies.
RUN set -x \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy in the 'package' directory from the build image.
COPY --from=build /src/package /opt/portier-broker
WORKDIR /opt/portier-broker

# Set image settings.
ENTRYPOINT ["/opt/portier-broker/portier-broker"]
USER portier-broker
ENV BROKER_LISTEN_IP=::
EXPOSE 3333
