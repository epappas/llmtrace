# Python Examples

This directory contains ready-to-run Python examples for LLMTrace integration.

## Examples

| File | Description | Use Case |
|------|-------------|----------|
| [`openai_basic.py`](openai_basic.py) | Basic OpenAI SDK integration | Getting started |
| [`openai_streaming.py`](openai_streaming.py) | Streaming responses with callbacks | Real-time applications |
| [`langchain_integration.py`](langchain_integration.py) | LangChain framework integration | AI applications |
| [`async_example.py`](async_example.py) | Async/await patterns | High-performance apps |

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install openai langchain langchain-openai
   ```

2. **Set your API key:**
   ```bash
   export OPENAI_API_KEY="your-openai-key"
   ```

3. **Start LLMTrace:**
   ```bash
   docker compose up -d  # or run LLMTrace locally
   ```

4. **Run an example:**
   ```bash
   python openai_basic.py
   ```

5. **Check traces:**
   ```bash
   curl http://localhost:8080/traces | jq
   ```

## Requirements

```
openai>=1.0.0
langchain>=0.1.0
langchain-openai>=0.1.0
requests>=2.28.0
```