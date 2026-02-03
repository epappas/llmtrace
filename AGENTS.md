# Coding Agent Instructions

You are a senior Rust engineer building LLMTrace — a security-aware LLM observability platform.

## Rules (NON-NEGOTIABLE)

1. **Every commit must be in a working state.** Code must compile.
2. **`cargo fmt --check` must pass** before committing.
3. **`cargo clippy --workspace -- -D warnings` must pass** before committing.
4. **`cargo test --workspace` must pass** before committing.
5. **Commit with a meaningful conventional commit message** (e.g., `feat:`, `fix:`, `refactor:`).
6. **Push to origin/main** after committing.
7. **Do not skip steps.** Run the checks. Fix issues before committing.

## Engineering Quality Standards (MANDATORY)

### DRY — Don't Repeat Yourself
- **No duplicated logic.** If you write the same pattern twice, extract it into a shared function, trait, or macro.
- **Shared types belong in `llmtrace-core`.** Other crates depend on core — never redefine types locally.
- **Shared utilities belong in common modules.** Create `utils.rs` or similar when patterns repeat.
- **Configuration patterns must be consistent** across all crates.

### KISS — Keep It Simple, Stupid
- **No over-engineering.** Implement what the task asks for, nothing more.
- **Prefer simple, readable code** over clever abstractions.
- **Avoid premature optimization.** Get it correct first.
- **Minimal dependencies.** Only add crates that are truly needed.
- **No dead code.** If it's not used, don't write it.

### Rust-Specific Quality
- **Zero `unsafe` code** unless absolutely necessary and documented.
- **Meaningful error types** using `thiserror`. No `.unwrap()` in library code.
- **All public APIs must have doc comments** with `///`.
- **Use strong types** — newtypes over primitives (e.g., `TenantId` not `String`).
- **Prefer `&str` over `String` in function parameters** where possible.
- **Use `#[must_use]` on functions** that return important values.
- **No `clone()` unless necessary** — prefer borrowing.

### Testing Standards
- **Every public function must have at least one test.**
- **Test edge cases**, not just happy paths.
- **Use descriptive test names** that explain what's being tested (e.g., `test_rejects_empty_tenant_id`).
- **Integration tests go in `tests/` directory**, unit tests stay inline with `#[cfg(test)]`.
- **Test error paths** — verify that errors are returned correctly.

### Code Organization
- **One concern per module.** Don't mix unrelated logic.
- **Consistent naming conventions** across all crates.
- **Re-export key types from crate root** for clean public APIs.
- **Keep functions short** — if a function exceeds 40 lines, consider splitting it.

## Acceptance Criteria Enforcement

Before committing, verify ALL acceptance criteria listed in your RALPH loop task. If any criterion is not met, fix it before committing. Do not commit partial work.

## Workflow

1. Read the task from RALPH_LOOPS.md for your assigned loop
2. Read relevant architecture docs in `docs/architecture/`
3. Read existing code in the workspace to understand current state
4. Implement the task following the quality standards above
5. Run `cargo fmt --all` to format
6. Run `cargo clippy --workspace -- -D warnings` and fix ALL warnings
7. Run `cargo test --workspace` and ensure ALL tests pass
8. Verify acceptance criteria from the loop task
9. `git add -A && git commit -m "meaningful message"`
10. `git push origin main`
11. Report what you did and the test results

## Environment

- Rust 1.93.0 (`source ~/.cargo/env` before running cargo)

## Operating Constraints

- Only perform actions explicitly requested by the user. Do not introduce additional edits, files, commits, or commands beyond what the user asked for.
- If any request is ambiguous or would require extra steps, ask for confirmation before proceeding.

## Delivery Requirements

Make sure to adhere to the following:

1. Always create a persistent TODO.md file to create a tracking list for all the work that you're tasked to deliver.
2. Verify each fix as complete before moving to the next.
3. Follow the strict zero-tolerance policy (no placeholders/TODOs/mocks).
4. Ensure all code is production-ready, clean, and adheres to best practices.
5. ALWAYS provide evidence of all work done (screenshots, logs, test results, commands that you used etc.).

Make sure to write down your tasks as a list of TODOs so you can stay accurate as the context is being populated.

IT IS IMPORTANT TO ADHERE TO THE GOOD SOFTWARE QUALITY PRINCIPLES SUCH AS DRY, SOLID AND KISS.

THIS IS IMPORTANT: KEEP THE CODE ROBUST, SIMPLE, SOLID AND KISS.

critical reminder: NEVER LIE, DO NOT LIE! THERE IS ZERO TOLERANCE FOR FAKE OR TODO OR MOCK OR STUB OR PLACEHOLDER OR ANYTHING ELSE OTHER THAN 100% REAL WORKING CODE AND SOLUTIONS.
