# Node.js Examples

Ready-to-run Node.js examples for LLMTrace integration.

## Examples

| File | Description | Use Case |
|------|-------------|----------|
| [`openai_basic.js`](openai_basic.js) | Basic OpenAI SDK integration | Getting started |
| [`streaming.js`](streaming.js) | Streaming responses and error handling | Real-time apps |
| [`typescript_example.ts`](typescript_example.ts) | TypeScript integration | Type-safe development |

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install openai dotenv
   # For TypeScript example:
   npm install -D typescript @types/node ts-node
   ```

2. **Create `.env` file:**
   ```bash
   echo "OPENAI_API_KEY=your-openai-key" > .env
   ```

3. **Start LLMTrace:**
   ```bash
   docker compose up -d
   ```

4. **Run an example:**
   ```bash
   node openai_basic.js
   # or for TypeScript:
   npx ts-node typescript_example.ts
   ```

## Package.json

```json
{
  "dependencies": {
    "openai": "^4.0.0",
    "dotenv": "^16.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "@types/node": "^20.0.0",
    "ts-node": "^10.9.0"
  }
}
```