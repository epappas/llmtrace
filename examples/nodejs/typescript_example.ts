#!/usr/bin/env node

/**
 * TypeScript OpenAI integration with LLMTrace
 * 
 * Demonstrates type-safe OpenAI usage, custom interfaces,
 * and structured data handling.
 */

import OpenAI from 'openai';
import type { ChatCompletionMessageParam, ChatCompletionCreateParams } from 'openai/resources/chat/completions';
import dotenv from 'dotenv';

dotenv.config();

// Custom interfaces for structured responses
interface CodeExplanation {
  language: string;
  complexity: 'beginner' | 'intermediate' | 'advanced';
  explanation: string;
  keyPoints: string[];
  timeToLearn: string;
}

interface LLMTraceMetrics {
  trace_id: string;
  model_name: string;
  duration_ms: number;
  total_tokens: number;
  cost_usd?: number;
  security_score?: number;
}

interface SecurityFinding {
  finding_id: string;
  finding_type: 'prompt_injection' | 'pii_detection' | 'data_leakage';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
}

class LLMTraceClient {
  private openai: OpenAI;
  private baseUrl: string;

  constructor(apiKey: string, baseUrl: string = 'http://localhost:8080/v1') {
    this.openai = new OpenAI({
      baseURL: baseUrl,
      apiKey: apiKey,
      timeout: 30000
    });
    this.baseUrl = baseUrl.replace('/v1', '');
  }

  async chatCompletion(
    messages: ChatCompletionMessageParam[],
    options: Partial<ChatCompletionCreateParams> = {}
  ): Promise<OpenAI.Chat.Completions.ChatCompletion> {
    const params: ChatCompletionCreateParams = {
      model: 'gpt-4',
      messages,
      temperature: 0.7,
      max_tokens: 1000,
      ...options
    };

    return await this.openai.chat.completions.create(params);
  }

  async getTraces(limit: number = 10): Promise<LLMTraceMetrics[]> {
    try {
      const response = await fetch(`${this.baseUrl}/traces?limit=${limit}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.warn('Could not fetch traces:', (error as Error).message);
      return [];
    }
  }

  async getSecurityFindings(): Promise<SecurityFinding[]> {
    try {
      const response = await fetch(`${this.baseUrl}/security/findings`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.warn('Could not fetch security findings:', (error as Error).message);
      return [];
    }
  }

  async streamCompletion(
    messages: ChatCompletionMessageParam[],
    onToken?: (token: string) => void
  ): Promise<string> {
    const stream = await this.openai.chat.completions.create({
      model: 'gpt-4',
      messages,
      stream: true,
      max_tokens: 500
    });

    let content = '';
    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content || '';
      if (delta) {
        content += delta;
        onToken?.(delta);
      }
    }

    return content;
  }
}

async function structuredResponseExample(client: LLMTraceClient): Promise<void> {
  console.log('🏗️ Structured Response Example');

  const prompt: ChatCompletionMessageParam[] = [
    {
      role: 'system',
      content: `You are a programming tutor. Respond with a JSON object matching this schema:
      {
        "language": string,
        "complexity": "beginner" | "intermediate" | "advanced",
        "explanation": string,
        "keyPoints": string[],
        "timeToLearn": string
      }`
    },
    {
      role: 'user',
      content: 'Explain async/await in JavaScript'
    }
  ];

  try {
    const response = await client.chatCompletion(prompt, {
      temperature: 0.3  // Lower temperature for structured output
    });

    const content = response.choices[0].message.content;
    if (!content) throw new Error('No content in response');

    // Parse structured response
    const codeExplanation: CodeExplanation = JSON.parse(content);

    console.log(`📚 Language: ${codeExplanation.language}`);
    console.log(`⭐ Complexity: ${codeExplanation.complexity}`);
    console.log(`📝 Explanation: ${codeExplanation.explanation}`);
    console.log(`🔑 Key points:`);
    codeExplanation.keyPoints.forEach(point => {
      console.log(`   • ${point}`);
    });
    console.log(`⏱️ Time to learn: ${codeExplanation.timeToLearn}`);

  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error('❌ Failed to parse JSON response');
    } else {
      console.error('❌ Structured response error:', (error as Error).message);
    }
  }
}

async function streamingTypedExample(client: LLMTraceClient): Promise<void> {
  console.log('\n🌊 Streaming Typed Example');

  const messages: ChatCompletionMessageParam[] = [
    { role: 'user', content: 'Write a haiku about TypeScript' }
  ];

  console.log('📝 Generating haiku...');
  console.log('-'.repeat(30));

  let tokenCount = 0;
  const startTime = Date.now();

  try {
    const content = await client.streamCompletion(messages, (token: string) => {
      process.stdout.write(token);
      tokenCount++;
    });

    const duration = Date.now() - startTime;
    console.log(`\n\n✅ Generated ${tokenCount} tokens in ${duration}ms`);

  } catch (error) {
    console.error('❌ Streaming error:', (error as Error).message);
  }
}

async function conversationWithTypes(client: LLMTraceClient): Promise<void> {
  console.log('\n💭 Typed Conversation Example');

  interface ConversationTurn {
    user: string;
    assistant?: string;
    tokens?: number;
    duration?: number;
  }

  const conversation: ConversationTurn[] = [
    { user: 'What are the benefits of using TypeScript?' },
    { user: 'How does it help with large applications?' },
    { user: 'What are some best practices?' }
  ];

  const messages: ChatCompletionMessageParam[] = [
    { role: 'system', content: 'You are a TypeScript expert. Give concise, practical answers.' }
  ];

  for (const turn of conversation) {
    console.log(`\n👤 User: ${turn.user}`);
    
    messages.push({ role: 'user', content: turn.user });

    try {
      const startTime = Date.now();
      const response = await client.chatCompletion(messages, { max_tokens: 150 });
      const duration = Date.now() - startTime;

      const assistantReply = response.choices[0].message.content || 'No response';
      turn.assistant = assistantReply;
      turn.tokens = response.usage?.total_tokens;
      turn.duration = duration;

      console.log(`🤖 Assistant: ${assistantReply}`);
      console.log(`📊 ${turn.tokens} tokens, ${duration}ms`);

      messages.push({ role: 'assistant', content: assistantReply });

    } catch (error) {
      console.error(`❌ Conversation error: ${(error as Error).message}`);
      break;
    }
  }

  // Summary
  const totalTokens = conversation.reduce((sum, turn) => sum + (turn.tokens || 0), 0);
  const totalDuration = conversation.reduce((sum, turn) => sum + (turn.duration || 0), 0);
  
  console.log(`\n📈 Conversation summary: ${totalTokens} tokens, ${totalDuration}ms total`);
}

async function functionCallingTyped(client: LLMTraceClient): Promise<void> {
  console.log('\n🔧 Typed Function Calling Example');

  interface WeatherParams {
    location: string;
    unit: 'celsius' | 'fahrenheit';
  }

  interface WeatherResult {
    temperature: number;
    condition: string;
    humidity: number;
  }

  const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = [
    {
      type: 'function',
      function: {
        name: 'get_weather',
        description: 'Get current weather for a location',
        parameters: {
          type: 'object',
          properties: {
            location: { type: 'string', description: 'City name' },
            unit: { type: 'string', enum: ['celsius', 'fahrenheit'] }
          },
          required: ['location']
        }
      }
    }
  ];

  try {
    const response = await client.chatCompletion([
      { role: 'user', content: 'What\'s the weather like in London in Celsius?' }
    ], {
      tools,
      tool_choice: 'auto'
    });

    const message = response.choices[0].message;
    
    if (message.tool_calls) {
      const toolCall = message.tool_calls[0];
      console.log(`🔧 Function: ${toolCall.function.name}`);
      
      const params: WeatherParams = JSON.parse(toolCall.function.arguments);
      console.log(`📍 Location: ${params.location}`);
      console.log(`🌡️  Unit: ${params.unit}`);
      
      // Simulate function execution
      const weatherResult: WeatherResult = {
        temperature: 15,
        condition: 'Partly cloudy',
        humidity: 65
      };
      
      console.log(`☁️ Weather: ${weatherResult.condition}, ${weatherResult.temperature}°${params.unit === 'celsius' ? 'C' : 'F'}`);
    } else {
      console.log(`💬 Response: ${message.content}`);
    }

  } catch (error) {
    console.error('❌ Function calling error:', (error as Error).message);
  }
}

async function analyzeTraces(client: LLMTraceClient): Promise<void> {
  console.log('\n📊 Trace Analysis');

  const traces = await client.getTraces(5);
  const findings = await client.getSecurityFindings();

  if (traces.length > 0) {
    console.log(`📈 Found ${traces.length} recent traces:`);
    
    traces.forEach((trace, index) => {
      console.log(`  ${index + 1}. ${trace.trace_id.substring(0, 8)}... - ${trace.model_name}`);
      console.log(`     ⏱️ ${trace.duration_ms}ms, 📊 ${trace.total_tokens} tokens`);
      if (trace.cost_usd) {
        console.log(`     💰 $${trace.cost_usd.toFixed(4)}`);
      }
    });

    // Calculate averages
    const avgDuration = traces.reduce((sum, t) => sum + t.duration_ms, 0) / traces.length;
    const avgTokens = traces.reduce((sum, t) => sum + t.total_tokens, 0) / traces.length;
    
    console.log(`\n📊 Averages: ${avgDuration.toFixed(0)}ms, ${avgTokens.toFixed(0)} tokens per request`);
  }

  if (findings.length > 0) {
    console.log(`\n⚠️ Security findings: ${findings.length}`);
    findings.slice(0, 3).forEach(finding => {
      console.log(`  • ${finding.severity.toUpperCase()}: ${finding.title}`);
    });
  } else {
    console.log('\n✅ No security issues detected');
  }
}

async function main(): Promise<void> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.error('❌ Please set OPENAI_API_KEY environment variable');
    process.exit(1);
  }

  console.log('🔷 TypeScript + LLMTrace Integration');
  console.log('='.repeat(50));

  const client = new LLMTraceClient(apiKey);

  try {
    await structuredResponseExample(client);
    await streamingTypedExample(client);
    await conversationWithTypes(client);
    await functionCallingTyped(client);
    
    // Give LLMTrace time to process
    await new Promise<void>(resolve => setTimeout(resolve, 2000));
    await analyzeTraces(client);

    console.log('\n✅ All TypeScript examples completed!');
    console.log('🔍 View traces: http://localhost:8080/traces');

  } catch (error) {
    console.error('❌ Example error:', (error as Error).message);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n⏹️ Gracefully shutting down...');
  process.exit(0);
});

main().catch(console.error);