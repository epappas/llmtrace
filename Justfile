set shell := ["bash", "-lc"]

_default:
    @just --list

fmt:
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

check: fmt clippy test
