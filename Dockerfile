# syntax=docker/dockerfile:1

# This Dockerfile creates an image with a release build of the broker.
#
# To run a container:
#
#   docker run -v /srv/portier-broker:/data:ro portier/broker /data/config.toml
#

# Stage 1: Build the broker in release mode.
FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /build
COPY . .
# To create a debug build instead, add: --build-arg cargo_flags=""
ARG cargo_flags="--release --locked"
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/build/target,sharing=locked \
  cargo build $cargo_flags && \
  cp ./target/release/portier-broker /

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

# Stage 3: Prepare the base Alpine system.
# This stage is separate, because release images only use this,
# then copy in the release tarball as a layer on top.
FROM alpine AS base
# Add a user and group first to make sure their IDs get assigned consistently,
# regardless of whatever dependencies get added.
RUN set -x \
  && addgroup -S -g 2000 portier-broker \
  && adduser -S -G portier-broker -u 2000 portier-broker
# Set image settings.
WORKDIR /opt/portier-broker
ENTRYPOINT ["/opt/portier-broker/portier-broker"]
USER portier-broker
ENV BROKER_LISTEN_IP=::
EXPOSE 3333

# Stage 4: Copy in the build and data files.
FROM base AS out
COPY --from=build /portier-broker /opt/portier-broker/
COPY --from=data /data /opt/portier-broker
