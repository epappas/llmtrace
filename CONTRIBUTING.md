# Contributing to LLMTrace

LLMTrace is an open-source LLM security and observability proxy built in Rust. We welcome contributions of all kinds — bug fixes, new detectors, documentation improvements, and performance optimizations.

## Prerequisites

- **Rust 1.75+** (stable toolchain)
- **Docker** (for storage services: ClickHouse, PostgreSQL, Redis)
- **Python 3.10+** (for benchmark scripts only)

## Building

```bash
# Build all crates
cargo build --workspace

# Build release with ML security models
cargo build --release --features ml

# Build proxy only
cargo build -p llmtrace --release --features ml
```

## Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p llmtrace-security
cargo test -p llmtrace
```

## Code Style

All code must pass formatting and linting checks before merge:

```bash
# Format
cargo fmt --all

# Lint (must pass with zero warnings)
cargo clippy --all-targets -- -D warnings
```

## Commit Format

Follow conventional commits:

```
type(scope): description
```

**Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

**Examples:**
- `feat(security): add PIGuard detector to ensemble`
- `fix(proxy): handle chunked transfer encoding in streaming`
- `docs(readme): update API endpoint paths`
- `test(benchmarks): add TensorTrust attack samples`

## Pull Request Process

1. **Branch from `main`** — use a descriptive branch name (e.g., `feat/piguard-detector`)
2. **Keep PRs focused** — one logical change per PR
3. **CI must be green** — formatting, linting, and all tests must pass
4. **Review required** — at least one maintainer approval before merge
5. **Rebase preferred** — keep a clean commit history

## Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or improvement |
| `good-first-issue` | Good for newcomers |
| `documentation` | Docs improvements |
| `security` | Security-related changes |
| `performance` | Performance improvements |

## Architecture Quick Reference

| Crate | Responsibility |
|-------|---------------|
| `llmtrace-core` | Shared types, traits, and configuration |
| `llmtrace` | HTTP proxy server, request/response handling, streaming ([crates.io](https://crates.io/crates/llmtrace)) |
| `llmtrace-security` | Security analysis engine: regex patterns, DeBERTa ML, InjecGuard, PIGuard, ensemble voting |
| `llmtrace-storage` | Storage backends: SQLite, PostgreSQL, ClickHouse, Redis |
| `llmtrace-sdk` | Rust SDK for programmatic access |
| `llmtrace-python` | Python SDK via PyO3 ([PyPI: llmtracing](https://pypi.org/project/llmtracing/)) |

### Security Ensemble Pipeline

The security engine uses a multi-detector majority voting approach:

1. **Regex patterns** — fast pattern matching for known injection signatures
2. **DeBERTa ML** — transformer-based prompt injection classifier
3. **InjecGuard** — specialized injection detection model
4. **PIGuard** — prompt injection guard model
5. **Ensemble voting** — majority vote across detectors determines final classification

## Getting Help

- **Bug reports** — [Open an issue](https://github.com/epappas/llmtrace/issues)
- **Questions** — [GitHub Discussions](https://github.com/epappas/llmtrace/discussions)
- **Security issues** — Email epappas@evalonlabs.com directly (do not open a public issue)
