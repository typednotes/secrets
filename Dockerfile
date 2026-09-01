# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p secrets-server \
    && cp target/release/secrets-server /app/secrets-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 secrets

WORKDIR /app
COPY --from=builder /app/secrets-server /usr/local/bin/secrets-server
USER secrets
EXPOSE 8200
ENTRYPOINT ["/usr/local/bin/secrets-server"]
