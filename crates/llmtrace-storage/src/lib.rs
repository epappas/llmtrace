//! Storage abstraction layer for LLMTrace
//!
//! This crate provides storage backends for persisting traces and security events.
//! The primary backend is SQLite (via `sqlx`), with an in-memory backend for testing.

mod memory;
mod sqlite;

pub use memory::InMemoryStorage;
pub use sqlite::SqliteStorage;
