# ============================================================================
# LLMTrace Proxy — Multi-stage Docker Build
# ============================================================================
# Produces a minimal runtime image (~30MB) with just the proxy binary.
#
# Build:  docker build -t llmtrace-proxy .
# Run:    docker run -p 8080:8080 --env-file .env llmtrace-proxy
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:latest AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static build-base protobuf-dev

WORKDIR /build

# Cache dependency build: copy manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/llmtrace-core/Cargo.toml crates/llmtrace-core/Cargo.toml
COPY crates/llmtrace-storage/Cargo.toml crates/llmtrace-storage/Cargo.toml
COPY crates/llmtrace-security/Cargo.toml crates/llmtrace-security/Cargo.toml
COPY crates/llmtrace-proxy/Cargo.toml crates/llmtrace-proxy/Cargo.toml
COPY crates/llmtrace-sdk/Cargo.toml crates/llmtrace-sdk/Cargo.toml
COPY crates/llmtrace-python/Cargo.toml crates/llmtrace-python/Cargo.toml
COPY benchmarks/Cargo.toml benchmarks/Cargo.toml

# Create stub lib.rs files so cargo can resolve the workspace
RUN mkdir -p crates/llmtrace-core/src && echo "" > crates/llmtrace-core/src/lib.rs && \
    mkdir -p crates/llmtrace-storage/src && echo "" > crates/llmtrace-storage/src/lib.rs && \
    mkdir -p crates/llmtrace-security/src && echo "" > crates/llmtrace-security/src/lib.rs && \
    mkdir -p crates/llmtrace-proxy/src && echo "fn main() {}" > crates/llmtrace-proxy/src/main.rs && echo "" > crates/llmtrace-proxy/src/lib.rs && \
    mkdir -p crates/llmtrace-sdk/src && echo "" > crates/llmtrace-sdk/src/lib.rs && \
    mkdir -p crates/llmtrace-python/src && echo "" > crates/llmtrace-python/src/lib.rs && \
    mkdir -p benchmarks/src && echo "" > benchmarks/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release --bin llmtrace-proxy 2>/dev/null || true

# Copy actual source and build for real
COPY crates/ crates/
COPY benchmarks/ benchmarks/
RUN touch crates/llmtrace-core/src/lib.rs \
    crates/llmtrace-storage/src/lib.rs \
    crates/llmtrace-security/src/lib.rs \
    crates/llmtrace-proxy/src/main.rs \
    crates/llmtrace-proxy/src/lib.rs \
    crates/llmtrace-sdk/src/lib.rs \
    crates/llmtrace-python/src/lib.rs \
    benchmarks/src/lib.rs

RUN cargo build --release --bin llmtrace-proxy

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM alpine:latest AS runtime

RUN apk add --no-cache ca-certificates tini

RUN addgroup -S llmtrace && adduser -S llmtrace -G llmtrace

COPY --from=builder /build/target/release/llmtrace-proxy /usr/local/bin/llmtrace-proxy
COPY config.example.yaml /etc/llmtrace/config.yaml

USER llmtrace
WORKDIR /home/llmtrace

EXPOSE 8080

ENTRYPOINT ["tini", "--"]
CMD ["llmtrace-proxy", "--config", "/etc/llmtrace/config.yaml"]
