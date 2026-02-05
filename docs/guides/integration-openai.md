# OpenAI SDK Integration Guide

This guide shows how to integrate LLMTrace with the official OpenAI SDKs for Python and Node.js. Integration is as simple as changing the base URL — no other code changes required.

## Python SDK Integration

### Installation

```bash
pip install openai
```

### Basic Setup

```python
import openai

# Before: Direct OpenAI connection
client = openai.OpenAI(api_key="your-openai-key")

# After: Route through LLMTrace (only change needed!)
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",  # LLMTrace proxy
    api_key="your-openai-key"
)
```

### Complete Example

```python
import openai
import os

# Set up client with LLMTrace
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key=os.getenv("OPENAI_API_KEY")
)

# Chat completions (non-streaming)
response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is the capital of France?"}
    ],
    temperature=0.7,
    max_tokens=100
)

print(response.choices[0].message.content)
```

### Streaming Example

```python
# Streaming works exactly the same
stream = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Write a short story about a robot."}
    ],
    stream=True,
    max_tokens=200
)

for chunk in stream:
    if chunk.choices[0].delta.content is not None:
        print(chunk.choices[0].delta.content, end="")
```

### Async Example

```python
import asyncio
from openai import AsyncOpenAI

async def main():
    client = AsyncOpenAI(
        base_url="http://localhost:8080/v1",
        api_key=os.getenv("OPENAI_API_KEY")
    )

    response = await client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": "Hello, async world!"}
        ]
    )

    print(response.choices[0].message.content)

asyncio.run(main())
```

### Function Calling

Function calling works transparently through LLMTrace:

```python
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather for a location",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City name"
                    }
                },
                "required": ["location"]
            }
        }
    }
]

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "What's the weather in Paris?"}
    ],
    tools=tools,
    tool_choice="auto"
)

# LLMTrace captures both the request and any function calls
```

### Image Analysis (Vision)

```python
# Vision API works seamlessly (use a vision-capable model for your provider)
response = client.chat.completions.create(
    model="vision-capable-model",
    messages=[
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's in this image?"},
                {
                    "type": "image_url",
                    "image_url": {
                        "url": "https://example.com/image.jpg"
                    }
                }
            ]
        }
    ],
    max_tokens=300
)
```

### Configuration with Environment Variables

```python
import os
from openai import OpenAI

# Use environment variables for flexibility
client = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    api_key=os.getenv("OPENAI_API_KEY")
)

# Development: export OPENAI_BASE_URL=http://localhost:8080/v1
# Production: don't set OPENAI_BASE_URL (uses default)
```

## Node.js SDK Integration

### Installation

```bash
npm install openai
```

### Basic Setup

```javascript
import OpenAI from 'openai';

// Before: Direct OpenAI connection
const openai = new OpenAI({
  apiKey: 'your-openai-key'
});

// After: Route through LLMTrace
const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',  // LLMTrace proxy
  apiKey: 'your-openai-key'
});
```

### Complete Example

```javascript
import OpenAI from 'openai';
import 'dotenv/config';

const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: process.env.OPENAI_API_KEY
});

async function main() {
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: 'What is the capital of France?' }
    ],
    temperature: 0.7,
    max_tokens: 100
  });

  console.log(response.choices[0].message.content);
}

main().catch(console.error);
```

### Streaming Example

```javascript
async function streamingExample() {
  const stream = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'user', content: 'Write a short story about a robot.' }
    ],
    stream: true,
    max_tokens: 200
  });

  for await (const chunk of stream) {
    process.stdout.write(chunk.choices[0]?.delta?.content || '');
  }
}

streamingExample();
```

### Error Handling

```javascript
import OpenAI from 'openai';

const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: process.env.OPENAI_API_KEY
});

async function handleErrors() {
  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: 'Hello!' }
      ]
    });

    console.log(response.choices[0].message.content);
  } catch (error) {
    if (error instanceof OpenAI.APIError) {
      console.error('OpenAI API error:', error.message);
      console.error('Status:', error.status);
      console.error('Code:', error.code);
    } else {
      console.error('Unexpected error:', error);
    }
  }
}
```

### TypeScript Example

```typescript
import OpenAI from 'openai';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';

const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: process.env.OPENAI_API_KEY!
});

async function typedExample(): Promise<void> {
  const messages: ChatCompletionMessageParam[] = [
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: 'Explain TypeScript to me.' }
  ];

  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages,
    temperature: 0.7
  });

  console.log(response.choices[0].message.content);
}
```

## Multi-Tenant Configuration

For applications serving multiple customers, use tenant headers. Tenant IDs must be valid UUIDs.

### Python Example

```python
import openai

def create_client_for_tenant(tenant_id: str) -> openai.OpenAI:
    return openai.OpenAI(
        base_url="http://localhost:8080/v1",
        api_key=os.getenv("OPENAI_API_KEY"),
        default_headers={
            "X-LLMTrace-Tenant-ID": tenant_id
        }
    )

# Usage
customer_a_client = create_client_for_tenant("550e8400-e29b-41d4-a716-446655440001")
customer_b_client = create_client_for_tenant("550e8400-e29b-41d4-a716-446655440002")

# Each client's requests are isolated in LLMTrace
response_a = customer_a_client.chat.completions.create(...)
response_b = customer_b_client.chat.completions.create(...)
```

### Node.js Example

```javascript
function createClientForTenant(tenantId) {
  return new OpenAI({
    baseURL: 'http://localhost:8080/v1',
    apiKey: process.env.OPENAI_API_KEY,
    defaultHeaders: {
      'X-LLMTrace-Tenant-ID': tenantId
    }
  });
}

const customerAClient = createClientForTenant('550e8400-e29b-41d4-a716-446655440001');
const customerBClient = createClientForTenant('550e8400-e29b-41d4-a716-446655440002');
```

## Fallback Strategy

Implement graceful fallback to direct OpenAI if LLMTrace is unavailable:

### Python Fallback

```python
import openai
import requests
from urllib.parse import urlparse

def create_resilient_client():
    llmtrace_url = "http://localhost:8080"

    # Check if LLMTrace is available
    try:
        response = requests.get(f"{llmtrace_url}/health", timeout=2)
        if response.status_code == 200:
            print("Using LLMTrace proxy")
            return openai.OpenAI(
                base_url=f"{llmtrace_url}/v1",
                api_key=os.getenv("OPENAI_API_KEY")
            )
    except requests.RequestException:
        pass

    print("LLMTrace unavailable, falling back to direct OpenAI")
    return openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Usage
client = create_resilient_client()
```

### Node.js Fallback

```javascript
import axios from 'axios';

async function createResilientClient() {
  const llmtraceUrl = 'http://localhost:8080';

  try {
    await axios.get(`${llmtraceUrl}/health`, { timeout: 2000 });
    console.log('Using LLMTrace proxy');
    return new OpenAI({
      baseURL: `${llmtraceUrl}/v1`,
      apiKey: process.env.OPENAI_API_KEY
    });
  } catch (error) {
    console.log('LLMTrace unavailable, falling back to direct OpenAI');
    return new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
  }
}

const client = await createResilientClient();
```

## Configuration Options

### Tenant, Agent, and Provider Headers

LLMTrace recognizes the following optional headers:

- `X-LLMTrace-Tenant-ID` (UUID)
- `X-LLMTrace-Agent-ID` (string, used for cost caps)
- `X-LLMTrace-Provider` (override provider detection)

```python
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key=os.getenv("OPENAI_API_KEY"),
    default_headers={
        "X-LLMTrace-Tenant-ID": "550e8400-e29b-41d4-a716-446655440001",
        "X-LLMTrace-Agent-ID": "research-agent",
        "X-LLMTrace-Provider": "openai"
    }
)
```

```javascript
const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: process.env.OPENAI_API_KEY,
  defaultHeaders: {
    'X-LLMTrace-Tenant-ID': '550e8400-e29b-41d4-a716-446655440001',
    'X-LLMTrace-Agent-ID': 'research-agent',
    'X-LLMTrace-Provider': 'openai'
  }
});
```

### Timeout Configuration

```python
# Python: Set custom timeouts
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key=os.getenv("OPENAI_API_KEY"),
    timeout=30.0  # 30 second timeout
)
```

```javascript
// Node.js: Set custom timeouts
const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 30 * 1000  // 30 second timeout
});
```

## Monitoring Integration

### View Traces for Your Requests

After making requests through LLMTrace, you can inspect the captured traces:

```bash
# Get recent traces
curl http://localhost:8080/api/v1/traces | jq '.data[0]'

# Get specific trace by ID
curl http://localhost:8080/api/v1/traces/7aa2c9b2-1fb1-4d64-9a4f-0c19c7f0a2b1 | jq

# Check for security findings
curl http://localhost:8080/api/v1/security/findings | jq '.data[0]'
```

If auth is enabled, include `Authorization: Bearer llmt_...`.

### API Integration

```python
import requests

def get_trace_stats():
    response = requests.get("http://localhost:8080/api/v1/stats")
    return response.json()

def get_recent_security_findings():
    response = requests.get("http://localhost:8080/api/v1/security/findings")
    return response.json()

# Check stats after your requests
stats = get_trace_stats()
print(stats)

findings = get_recent_security_findings()
if findings.get("data"):
    print(f" {len(findings['data'])} security findings detected")
```

## Troubleshooting

### Common Issues

**Connection refused:**
```bash
# Check if LLMTrace is running
curl http://localhost:8080/health
```

**SSL certificate errors:**
```python
# For self-signed certificates, use:
import ssl
import openai

client = openai.OpenAI(
    base_url="https://localhost:8443/v1",
    api_key=os.getenv("OPENAI_API_KEY")
)

# Note: In production, use proper certificates
```

**Timeout issues:**
```python
# Increase timeout for slow networks
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key=os.getenv("OPENAI_API_KEY"),
    timeout=60.0  # 60 seconds
)
```

## Next Steps

- **[LangChain Integration](integration-langchain.md)** — Use with LangChain framework
- **[API Guide](API.md)** — REST queries + proxy paths
- **[Custom Policies](custom-policies.md)** — Configure security and budgets

**Need help?** [Open an issue](https://github.com/epappas/llmtrace/issues) or check the [troubleshooting guide](../deployment/troubleshooting.md).
