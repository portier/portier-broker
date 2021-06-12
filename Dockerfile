# This Dockerfile creates an image with a release build of the broker.
#
# To run a container:
#
#   docker run -v /srv/portier-broker:/data:ro portier/broker /data/config.toml
#

# Stage 1: Build the broker in release mode.
FROM rust:1-bullseye AS build
WORKDIR /build
COPY . .
RUN cargo build --release --locked

# Stage 2: Prepare data files.
FROM alpine AS data
WORKDIR /data
COPY lang ./lang
COPY res ./res
COPY tmpl ./tmpl
# Allow overriding via a build arg. We throw away our earlier work, but that's
# fine, because only the last stage matters for the output image.
ARG data_url
RUN if [ -n "$data_url" ]; then \
  rm -fr lang res tmpl; \
  wget -O - "$data_url" | tar -xz; \
fi
# Don't keep translation source files.
RUN rm -f ./lang/*.po

# Stage 3: Prepare the base Debian system.
# This stage is separate, because release images only use this,
# then copy in the release tarball as a layer on top.
FROM debian:bullseye AS base
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
# Set image settings.
WORKDIR /opt/portier-broker
ENTRYPOINT ["/opt/portier-broker/portier-broker"]
USER portier-broker
ENV BROKER_LISTEN_IP=::
EXPOSE 3333

# Stage 4: Copy in the build and data files.
FROM base AS out
COPY --from=build /build/target/release/portier-broker /opt/portier-broker/
COPY --from=data /data /opt/portier-broker
