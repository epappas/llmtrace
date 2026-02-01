# Installation Guide

This guide covers all the ways to install and deploy LLMTrace, from local development to production environments.

## Quick Install Options

| Method | Best for | Setup Time | Dependencies |
|--------|----------|------------|--------------|
| [Docker Compose](#docker-compose) | **Getting started** | 30 seconds | Docker |
| [Docker](#docker) | Simple deployments | 1 minute | Docker |
| [Kubernetes](#kubernetes) | Production | 5 minutes | Kubernetes |
| [Binary](#binary-releases) | Custom deployments | 2 minutes | None |
| [From Source](#from-source) | Development | 5 minutes | Rust toolchain |

## Docker Compose

**Recommended for new users.** Includes proxy + dashboard + SQLite database.

```bash
# 1. Get the compose file
curl -o compose.yaml https://raw.githubusercontent.com/epappas/llmtrace/main/compose.yaml

# 2. Start everything
docker compose up -d

# 3. Verify
curl http://localhost:8080/health
open http://localhost:3000  # Dashboard
```

### Compose file breakdown:

```yaml
services:
  llmtrace:
    image: epappas/llmtrace:latest
    ports:
      - "8080:8080"
    environment:
      LLMTRACE_UPSTREAM_URL: "https://api.openai.com"
      LLMTRACE_STORAGE_PROFILE: "lite"
    volumes:
      - ./data:/data
    
  dashboard:
    image: epappas/llmtrace-dashboard:latest
    ports:
      - "3000:3000"
    environment:
      LLMTRACE_API_URL: "http://llmtrace:8080"
    depends_on:
      - llmtrace
```

**What you get:**
- Proxy on `:8080`
- Dashboard on `:3000`
- SQLite database in `./data/`
- Automatic restarts

## Docker

For minimal deployments or custom orchestration:

### Basic setup:

```bash
docker run -d \
  --name llmtrace \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e LLMTRACE_UPSTREAM_URL=https://api.openai.com \
  -e LLMTRACE_STORAGE_PROFILE=lite \
  epappas/llmtrace:latest
```

### With custom configuration:

```bash
# Create config directory
mkdir -p ./config

# Copy and edit config
curl -o ./config/config.yaml \
  https://raw.githubusercontent.com/epappas/llmtrace/main/config.example.yaml

# Run with config file
docker run -d \
  --name llmtrace \
  -p 8080:8080 \
  -v $(pwd)/config:/config \
  -v $(pwd)/data:/data \
  epappas/llmtrace:latest \
  --config /config/config.yaml
```

### Available images:

| Image | Description | Size |
|-------|-------------|------|
| `epappas/llmtrace:latest` | Latest stable release | ~50MB |
| `epappas/llmtrace:v1.2.0` | Specific version | ~50MB |
| `epappas/llmtrace:nightly` | Development builds | ~50MB |
| `epappas/llmtrace-dashboard:latest` | Web dashboard | ~25MB |

## Kubernetes

### Quick deploy with Helm (Recommended):

```bash
# Add LLMTrace Helm repository
helm repo add llmtrace https://charts.llmtrace.dev
helm repo update

# Install with defaults
helm install llmtrace llmtrace/llmtrace

# Or with custom values
helm install llmtrace llmtrace/llmtrace -f values.yaml
```

### Example values.yaml:

```yaml
# values.yaml
image:
  tag: "v1.2.0"

config:
  upstreamUrl: "https://api.openai.com"
  storage:
    profile: "production"
    postgres:
      host: "postgres.default.svc.cluster.local"
      database: "llmtrace"

resources:
  limits:
    cpu: "1"
    memory: "512Mi"
  requests:
    cpu: "500m"
    memory: "256Mi"

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10

ingress:
  enabled: true
  hostname: "llmtrace.company.com"
  tls:
    enabled: true
```

### Raw Kubernetes manifests:

```bash
# Apply all manifests
kubectl apply -f https://raw.githubusercontent.com/epappas/llmtrace/main/deployments/kubernetes/

# Or download and customize
curl -o k8s-manifest.yaml \
  https://raw.githubusercontent.com/epappas/llmtrace/main/deployments/kubernetes/all-in-one.yaml
```

### Production Kubernetes setup:

For production, you'll want:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llmtrace
spec:
  replicas: 3
  selector:
    matchLabels:
      app: llmtrace
  template:
    metadata:
      labels:
        app: llmtrace
    spec:
      containers:
      - name: llmtrace
        image: epappas/llmtrace:v1.2.0
        ports:
        - containerPort: 8080
        env:
        - name: LLMTRACE_STORAGE_POSTGRES_URL
          valueFrom:
            secretKeyRef:
              name: llmtrace-db
              key: postgres-url
        - name: LLMTRACE_STORAGE_REDIS_URL
          valueFrom:
            secretKeyRef:
              name: llmtrace-cache
              key: redis-url
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"
```

## Binary Releases

Download pre-built binaries from [GitHub releases](https://github.com/epappas/llmtrace/releases):

### Linux:

```bash
# Download latest release
curl -L -o llmtrace-proxy \
  https://github.com/epappas/llmtrace/releases/latest/download/llmtrace-proxy-linux-x86_64

# Make executable and move to PATH
chmod +x llmtrace-proxy
sudo mv llmtrace-proxy /usr/local/bin/

# Verify installation
llmtrace-proxy --version
```

### macOS:

```bash
# Intel Macs
curl -L -o llmtrace-proxy \
  https://github.com/epappas/llmtrace/releases/latest/download/llmtrace-proxy-macos-x86_64

# Apple Silicon Macs  
curl -L -o llmtrace-proxy \
  https://github.com/epappas/llmtrace/releases/latest/download/llmtrace-proxy-macos-aarch64

chmod +x llmtrace-proxy
sudo mv llmtrace-proxy /usr/local/bin/
```

### Windows:

```powershell
# Download from releases page or use curl
curl -L -o llmtrace-proxy.exe `
  https://github.com/epappas/llmtrace/releases/latest/download/llmtrace-proxy-windows.exe

# Add to PATH or run directly
.\llmtrace-proxy.exe --version
```

### Running the binary:

```bash
# Get example config
curl -o config.yaml \
  https://raw.githubusercontent.com/epappas/llmtrace/main/config.example.yaml

# Start the proxy
llmtrace-proxy --config config.yaml

# Or with environment variables
LLMTRACE_UPSTREAM_URL=https://api.openai.com llmtrace-proxy
```

## From Source

For development or custom builds:

### Prerequisites:

- **Rust 1.70+** (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Git**

### Build steps:

```bash
# 1. Clone repository
git clone https://github.com/epappas/llmtrace
cd llmtrace

# 2. WSL2 users: use tmp directory to avoid filesystem issues
export CARGO_TARGET_DIR=/tmp/llmtrace-target

# 3. Build release binary
cargo build --release

# 4. Binary location
ls -la target/release/llmtrace-proxy

# 5. Test the build
./target/release/llmtrace-proxy --version
```

### Development build:

```bash
# Faster compilation for development
cargo build

# Run tests
cargo test --workspace

# Run with file watching
cargo install cargo-watch
cargo watch -x "run -- --config config.yaml"
```

### Cross-compilation:

```bash
# Install cross-compilation targets
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl

# Build for Alpine Linux (static binary)
cargo build --release --target x86_64-unknown-linux-musl

# Build for ARM64
cargo build --release --target aarch64-unknown-linux-musl
```

## Python SDK Installation

The Python SDK provides direct integration without needing the proxy:

```bash
# Install from PyPI (when available)
pip install llmtrace-python

# Or build from source
cd crates/llmtrace-python
pip install maturin
maturin develop
```

### Using the Python SDK:

```python
import llmtrace
import openai

# Configure tracer
tracer = llmtrace.configure({
    "enable_security": True,
    "storage_path": "./traces.db"
})

# Instrument OpenAI client
client = openai.OpenAI()
client = llmtrace.instrument(client, tracer=tracer)

# Use normally - traces are captured automatically
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

## System Requirements

### Minimum requirements:

- **CPU:** 1 core
- **Memory:** 256MB
- **Storage:** 100MB + trace data
- **Network:** Outbound HTTPS (443) to LLM providers

### Recommended for production:

- **CPU:** 2+ cores
- **Memory:** 512MB+ 
- **Storage:** 10GB+ SSD
- **Network:** Low-latency connection to LLM providers

### Storage scaling:

| Requests/day | Storage/month | Recommended backend |
|--------------|---------------|-------------------|
| < 10K | < 100MB | SQLite |
| 10K - 100K | 100MB - 1GB | PostgreSQL |
| 100K+ | 1GB+ | PostgreSQL + ClickHouse |

## Configuration

### Environment variables:

| Variable | Purpose | Example |
|----------|---------|---------|
| `LLMTRACE_UPSTREAM_URL` | LLM provider URL | `https://api.openai.com` |
| `LLMTRACE_LISTEN_ADDR` | Listen address | `0.0.0.0:8080` |
| `LLMTRACE_STORAGE_PROFILE` | Storage backend | `lite`, `production` |
| `LLMTRACE_LOG_LEVEL` | Log verbosity | `info`, `debug` |

### Config file locations:

```bash
# Priority order (first found wins):
./config.yaml              # Current directory
~/.config/llmtrace/config.yaml   # User config
/etc/llmtrace/config.yaml        # System config
```

## Verification

After installation, verify everything works:

```bash
# 1. Health check
curl http://localhost:8080/health
# Should return: {"status": "healthy"}

# 2. Make a test request
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello!"}]}'

# 3. Check traces
curl http://localhost:8080/traces | jq length
# Should return: 1
```

## Troubleshooting

### Common issues:

**Binary not found:**
```bash
# Check if binary is in PATH
which llmtrace-proxy

# Or run with full path
./target/release/llmtrace-proxy --version
```

**Permission denied (Docker):**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Then log out and back in
```

**Port already in use:**
```bash
# Find what's using port 8080
sudo lsof -i :8080

# Use a different port
LLMTRACE_LISTEN_ADDR=0.0.0.0:9080 llmtrace-proxy
```

**WSL2 build issues:**
```bash
# Use tmp directory
export CARGO_TARGET_DIR=/tmp/llmtrace-target
cargo build --release
```

## Next Steps

- **[Quick Start Guide](quickstart.md)** — Get your first traces in 2 minutes
- **[Configuration Guide](configuration.md)** — Set up security policies and storage
- **[Integration Guides](../guides/)** — Connect with your specific tools and frameworks
- **[Production Deployment](../deployment/)** — Scale for production workloads

**Need help?** [Open an issue](https://github.com/epappas/llmtrace/issues) or check the [troubleshooting guide](../deployment/troubleshooting.md).