# LLMTrace

A security-aware LLM observability platform built in Rust.

## Overview

LLMTrace provides comprehensive observability and security monitoring for Large Language Model (LLM) applications. It captures traces of LLM interactions, analyzes them for security vulnerabilities like prompt injection attacks, and provides real-time monitoring capabilities.

## Features

- **Transparent Proxy**: Intercept LLM API calls without code changes
- **Security Analysis**: Real-time detection of prompt injection, PII leakage, and anomalies
- **Multi-Tenant**: Built-in tenant isolation for enterprise deployments
- **High Performance**: Rust-based implementation optimized for high throughput
- **Multiple Integrations**: Support for OpenAI, Anthropic, vLLM, SGLang, TGI, Ollama, and more
- **Python SDK**: Easy integration for Python applications
- **Compliance Ready**: SOC2, GDPR, and HIPAA compliance features

## Architecture

LLMTrace consists of several Rust crates:

- **`llmtrace-core`**: Core types, traits, and errors
- **`llmtrace-proxy`**: Transparent HTTP proxy server
- **`llmtrace-sdk`**: Embeddable SDK for Rust applications
- **`llmtrace-storage`**: Storage abstraction with SQLite backend
- **`llmtrace-security`**: Security analysis engines
- **`llmtrace-python`**: Python bindings via PyO3

## Quick Start

### Using the Transparent Proxy

1. Build the proxy server:
   ```bash
   cargo build --release --bin llmtrace-proxy
   ```

2. Run the proxy:
   ```bash
   ./target/release/llmtrace-proxy
   ```

3. Point your LLM client to the proxy instead of the original endpoint.

### Using the Rust SDK

```rust
use llmtrace_sdk::{LLMTracer, SDKConfig};
use llmtrace_core::{TenantId, LLMProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SDKConfig {
        tenant_id: TenantId::new(),
        ..Default::default()
    };
    
    let tracer = LLMTracer::new(config);
    
    // Your LLM calls here...
    
    tracer.flush().await?;
    Ok(())
}
```

### Using the Python SDK

```python
import llmtrace_python as llm

# Create a tracer
tracer = llm.create_tracer()

# Your LLM calls here...

# Flush traces
await tracer.flush()
```

## Security Features

- **Prompt Injection Detection**: Regex-based detection of common injection patterns
- **PII Detection**: Automatic detection of emails, phone numbers, SSNs, credit cards
- **Anomaly Detection**: Statistical analysis of usage patterns
- **Risk Scoring**: 0-100 risk scores for each interaction

## Development

### Prerequisites

- Rust 1.70+ (recommend using rustup)
- SQLite (for storage backend)

### Building

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --workspace -- -D warnings
```

### Project Structure

```
llmtrace/
├── crates/
│   ├── llmtrace-core/      # Core types and traits
│   ├── llmtrace-proxy/     # Proxy server binary
│   ├── llmtrace-sdk/       # Rust SDK
│   ├── llmtrace-storage/   # Storage backends
│   ├── llmtrace-security/  # Security analysis
│   └── llmtrace-python/    # Python bindings
└── docs/                    # Documentation
```

## Configuration

The proxy server uses YAML configuration:

```yaml
listen_addr: "0.0.0.0:8080"
upstream_url: "https://api.openai.com"
timeout_ms: 30000
enable_security_analysis: true
enable_trace_storage: true
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting: `cargo test && cargo fmt && cargo clippy`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Status

**Early Development** - This project is under active development. APIs may change frequently.

Current implementation status:
- [x] Basic workspace and crate structure
- [ ] Core types and traits (in progress)
- [ ] Proxy server implementation (planned)
- [ ] Security analysis engines (planned)
- [ ] Storage backends (planned)
- [ ] Python bindings (planned)