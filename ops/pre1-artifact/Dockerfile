# syntax=docker/dockerfile:1
# The retained pre-1 Linux binary must not inherit the host's glibc baseline.
# Keep this builder and the validation runtime on Debian Bookworm and pin both
# multi-platform manifests so amd64 and arm64 use the same declared contract.
FROM rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY migrations ./migrations
COPY schema ./schema
COPY parity ./parity

RUN cargo build --release --locked

FROM scratch AS artifact-export
COPY --from=builder /build/target/release/iicp-directory-rs /iicp-directory-rs
