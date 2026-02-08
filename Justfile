set shell := ["bash", "-lc"]

_default:
    @just --list

fmt:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    cargo fmt --all --check

fmt-write:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    cargo fmt --all

clippy:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    mkdir -p target/tmp; \
    TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    RUSTC_TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    CARGO_INCREMENTAL=0 \
    cargo clippy --workspace -- -D warnings

test:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    mkdir -p target/tmp; \
    TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    RUSTC_TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    CARGO_INCREMENTAL=0 \
    cargo test --workspace

bench:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    mkdir -p target/tmp; \
    TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    RUSTC_TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    CARGO_INCREMENTAL=0 \
    cargo run --bin benchmarks -- --output-dir benchmarks/results

benchmarks:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    mkdir -p target/tmp; \
    TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    RUSTC_TMPDIR=/root/workspace/spacejar/llmtrace/target/tmp \
    CARGO_INCREMENTAL=0 \
    cargo bench -p llmtrace-benchmarks

check: fmt clippy test

security:
    @set -euo pipefail; \
    source ~/.cargo/env; \
    cargo audit; \
    cargo deny check --all-features
