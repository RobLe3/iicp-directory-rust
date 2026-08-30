# Multi-stage build for the Rust directory control plane (#385).
# Used as a federation replica in docker-compose.federation.yml (#437/#436).
# Keep the builder on the same Debian generation as the runtime. The previous
# moving `rust:slim` digest used a newer glibc and produced a binary that could
# not start in the pinned Bookworm runtime image.
FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder
WORKDIR /build
# The Laravel-derived schema baseline and compatibility contract are embedded
# into the binary. Historical SQLx migrations remain source evidence but are
# never replayed at runtime.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY migrations ./migrations
COPY schema ./schema
# Compile-time taxonomy fixtures are part of the directory's policy contract.
# Keep them in the builder image so a production Docker build cannot silently
# diverge from the checked-in binary/test build.
COPY parity ./parity
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
# rustls (not OpenSSL) → only ca-certificates needed for outbound TLS to the seed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && groupadd --gid 10001 iicp \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin iicp \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/iicp-directory-rs /usr/local/bin/iicp-directory-rs
EXPOSE 8090
ENV RUST_LOG=info
USER 10001:10001
# DATABASE_URL → MySqlRepo (empty bootstrap or verify-only); IICP_REPLICA_MODE=true +
# IICP_SEED_URL=<seed> → federate (tail the seed's signed event log, mirror state).
CMD ["iicp-directory-rs"]
