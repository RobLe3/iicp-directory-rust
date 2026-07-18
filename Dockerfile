# Multi-stage build for the Rust directory control plane (#385).
# Used as a federation replica in docker-compose.federation.yml (#437/#436).
FROM rust:slim AS builder
WORKDIR /build
# The Laravel-derived schema baseline and compatibility contract are embedded
# into the binary. Historical SQLx migrations remain source evidence but are
# never replayed at runtime.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY schema ./schema
# Compile-time taxonomy fixtures are part of the directory's policy contract.
# Keep them in the builder image so a production Docker build cannot silently
# diverge from the checked-in binary/test build.
COPY parity ./parity
RUN cargo build --release --locked

FROM debian:bookworm-slim
# rustls (not OpenSSL) → only ca-certificates needed for outbound TLS to the seed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/iicp-directory-rs /usr/local/bin/iicp-directory-rs
EXPOSE 8090
ENV RUST_LOG=info
# DATABASE_URL → MySqlRepo (empty bootstrap or verify-only); IICP_REPLICA_MODE=true +
# IICP_SEED_URL=<seed> → federate (tail the seed's signed event log, mirror state).
CMD ["iicp-directory-rs"]
