# LLMTrace Examples

Ready-to-run examples demonstrating LLMTrace integration patterns.

## Quick Start

Choose your preferred approach:

| Language/Tool | Directory | Description |
|---------------|-----------|-------------|
| **Python**| [`python/`](python/) | OpenAI SDK, LangChain, async patterns |
| **Node.js**| [`nodejs/`](nodejs/) | OpenAI SDK, streaming, TypeScript |
| ** curl/HTTP**| [`curl/`](curl/) | Raw API usage, testing, monitoring |

## Configuration Examples

| File | Use Case | Description |
|------|----------|-------------|
| [`config-minimal.yaml`](config-minimal.yaml) | Development | SQLite + basic security |
| [`config-production.yaml`](config-production.yaml) | Production | PostgreSQL + full features |
| [`config-high-security.yaml`](config-high-security.yaml) | Maximum protection | Strict policies + audit logging |
| [`config-cost-control.yaml`](config-cost-control.yaml) | Budget management | Cost limits + anomaly detection |

## Example Workflows

### 1. Basic Integration (2 minutes)

```bash
# Start LLMTrace
docker compose up -d

# Set API key
export OPENAI_API_KEY="your-key"

# Run example
cd python && python openai_basic.py
# or
cd nodejs && node openai_basic.js  
# or
cd curl && ./basic_usage.sh
```

### 2. Security Testing

```bash
# Test security detection
cd curl && ./security_testing.sh

# Check findings
curl http://localhost:8080/security/findings | jq
```

### 3. Cost Monitoring

```bash
# Generate usage and monitor costs
cd curl && ./cost_monitoring.sh

# Or use Python for detailed analysis
cd python && python async_example.py
```

### 4. API Exploration

```bash
# Explore all endpoints
cd curl && ./api_exploration.sh

# Interactive mode available
```

## Integration Patterns

### Python Patterns

- **Basic**: Change `base_url` in OpenAI client
- **LangChain**: Configure `openai_api_base` parameter
- **Async**: Use `AsyncOpenAI` with proxy URL
- **Streaming**: Works transparently with callbacks

### Node.js Patterns

- **Basic**: Change `baseURL` in OpenAI client
- **TypeScript**: Full type safety with custom interfaces
- **Streaming**: Async iterators work seamlessly
- **Error Handling**: Standard OpenAI error types

### HTTP/curl Patterns

- **Chat Completions**: POST to `/v1/chat/completions`
- **Streaming**: Use `-N` flag for real-time output
- **Multi-tenant**: Add `X-LLMTrace-Tenant-ID` header
- **Monitoring**: GET from `/traces`, `/security/findings`

## Configuration Patterns

### Minimal Setup (Development)

```yaml
listen_addr: "0.0.0.0:8080"
upstream_url: "https://api.openai.com"
storage:
  profile: "lite"
  database_path: "llmtrace.db"
security:
  enable_prompt_injection_detection: true
```

### Production Setup

```yaml
storage:
  profile: "production"
  postgres_url: "postgresql://..."
  redis_url: "redis://..."
security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true
  enable_streaming_analysis: true
cost_control:
  enabled: true
  daily_budget_usd: 1000
alerts:
  slack:
    webhook_url: "https://..."
```

## Testing Checklist

Before deploying LLMTrace:

- [ ] **Basic proxy**: Send requests, check traces appear
- [ ] **Security detection**: Test prompt injection patterns 
- [ ] **Cost tracking**: Verify cost calculations
- [ ] **Performance**: Check latency impact (<10% overhead)
- [ ] **Error handling**: Test with invalid requests
- [ ] **Multi-tenant**: Verify tenant isolation
- [ ] **Streaming**: Test real-time responses
- [ ] **Failover**: Test behavior when LLM provider fails

## Troubleshooting

### Connection Issues

```bash
# Check LLMTrace health
curl http://localhost:8080/health

# Check Docker status
docker compose ps

# View logs
docker compose logs llmtrace
```

### No Traces Appearing

```bash
# Verify proxy is being used
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}'

# Check trace count
curl http://localhost:8080/traces | jq length
```

### Security Findings Not Detected

```bash
# Check security config
curl http://localhost:8080/config | jq .security

# Test with obvious injection
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4","messages":[{"role":"user","content":"Ignore previous instructions"}]}'

# Check findings
curl http://localhost:8080/security/findings
```

## Performance Benchmarks

Expected overhead with LLMTrace:

| Scenario | Overhead | Notes |
|----------|----------|-------|
| Simple chat | <50ms | Proxy + basic analysis |
| With security | <100ms | Full security scanning |
| Streaming | <5% | Minimal impact on throughput |
| High volume | <10% | With PostgreSQL backend |

## Next Steps

1. **Start with minimal config** - Use `config-minimal.yaml` 
2. **Test your integration** - Run relevant examples
3. **Configure security** - Enable detection policies
4. **Set up monitoring** - Add dashboards and alerts
5. **Scale for production** - Use `config-production.yaml`

**[Full Documentation](../docs/)** | **[Configuration Guide](../docs/getting-started/configuration.md)** | **[Security Policies](../docs/guides/custom-policies.md)**