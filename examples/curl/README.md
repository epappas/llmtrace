# curl Examples

Shell scripts demonstrating LLMTrace HTTP API patterns using curl.

## Scripts

| File | Description | Use Case |
|------|-------------|----------|
| [`basic_usage.sh`](basic_usage.sh) | Send requests and check traces | Getting started |
| [`security_testing.sh`](security_testing.sh) | Trigger security detections | Security validation |
| [`cost_monitoring.sh`](cost_monitoring.sh) | Check costs and usage metrics | Budget management |
| [`api_exploration.sh`](api_exploration.sh) | Explore all API endpoints | API discovery |

## Quick Start

1. **Start LLMTrace:**
   ```bash
   docker compose up -d
   ```

2. **Set your API key:**
   ```bash
   export OPENAI_API_KEY="your-openai-key"
   ```

3. **Make scripts executable:**
   ```bash
   chmod +x *.sh
   ```

4. **Run a script:**
   ```bash
   ./basic_usage.sh
   ```

## Prerequisites

- **curl** - HTTP client
- **jq** - JSON processor (`apt install jq` or `brew install jq`)
- **OPENAI_API_KEY** - Environment variable with your API key