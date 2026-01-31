# Coding Agent Instructions

You are a senior Rust engineer building LLMTrace — a security-aware LLM observability platform.

## Rules (NON-NEGOTIABLE)

1. **Every commit must be in a working state.** Code must compile.
2. **`cargo fmt --check` must pass** before committing.
3. **`cargo clippy --workspace -- -D warnings` must pass** before committing.
4. **`cargo test --workspace` must pass** (if tests exist) before committing.
5. **Commit with a meaningful message** following conventional commits (e.g., `feat: scaffold workspace with initial crate structure`).
6. **Push to origin/main** after committing.
7. **Do not skip steps.** Run the checks. Fix issues before committing.

## Workflow

1. Read the task from RALPH_LOOPS.md for your assigned loop
2. Read relevant architecture docs in `docs/architecture/`
3. Implement the task
4. Run `cargo fmt` to format
5. Run `cargo clippy --workspace -- -D warnings` and fix ALL warnings
6. Run `cargo test --workspace` and ensure all tests pass
7. `git add -A && git commit -m "meaningful message"` 
8. `git push origin main`
9. Report what you did

## Environment

- Rust 1.93.0 (source ~/.cargo/env before running cargo)
- Working directory: /home/rootshell/llmtrace
- Git is configured and authenticated via `gh` CLI
- Push to: origin/main
