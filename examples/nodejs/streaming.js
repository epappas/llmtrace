#!/usr/bin/env node

/**
 * Streaming responses and error handling with LLMTrace
 * 
 * Demonstrates streaming chat completions, error recovery,
 * and real-time token counting.
 */

import OpenAI from 'openai';
import dotenv from 'dotenv';

dotenv.config();

// Create OpenAI client with timeout and error handling
function createClient() {
  return new OpenAI({
    baseURL: 'http://localhost:8080/v1',
    apiKey: process.env.OPENAI_API_KEY,
    timeout: 30000,  // 30 second timeout
    maxRetries: 3
  });
}

async function basicStreamingExample() {
  console.log('🌊 Basic Streaming Example');
  
  const openai = createClient();

  try {
    console.log('📝 Generating a creative story...');
    console.log('-'.repeat(50));

    const stream = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: 'Write a short story about a time-traveling coffee shop (max 200 words)' }
      ],
      stream: true,
      max_tokens: 250
    });

    let tokenCount = 0;
    let firstTokenTime = null;
    const startTime = Date.now();

    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content || '';
      if (content) {
        if (firstTokenTime === null) {
          firstTokenTime = Date.now();
          const ttft = firstTokenTime - startTime;
          console.log(`\n⚡ Time to first token: ${ttft}ms\n`);
        }

        process.stdout.write(content);
        tokenCount++;
        
        // Add small delay to see streaming effect
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    const totalTime = Date.now() - startTime;
    const tokensPerSecond = (tokenCount / totalTime) * 1000;

    console.log(`\n\n✅ Streaming complete!`);
    console.log(`📊 Stats: ~${tokenCount} tokens in ${totalTime}ms (${tokensPerSecond.toFixed(1)} tok/s)`);

  } catch (error) {
    console.error(`❌ Streaming error: ${error.message}`);
  }
}

async function concurrentStreamsExample() {
  console.log('\n🔄 Concurrent Streams Example');

  const openai = createClient();
  
  const prompts = [
    'Explain machine learning in 2 sentences',
    'What is the capital of Australia?', 
    'How do you make scrambled eggs?'
  ];

  console.log(`🚀 Starting ${prompts.length} concurrent streams...`);

  const streamPromises = prompts.map(async (prompt, index) => {
    const id = String.fromCharCode(65 + index); // A, B, C
    
    try {
      const stream = await openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: prompt }],
        stream: true,
        max_tokens: 100
      });

      console.log(`\n[${id}] 📝 ${prompt}`);
      console.log(`[${id}] 💬 `, { end: '' });

      let content = '';
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta?.content || '';
        if (delta) {
          content += delta;
          process.stdout.write(delta);
        }
      }

      return { id, prompt, content: content.trim(), success: true };

    } catch (error) {
      console.log(`\n[${id}] ❌ Error: ${error.message}`);
      return { id, prompt, error: error.message, success: false };
    }
  });

  const results = await Promise.allSettled(streamPromises);
  const successful = results.filter(r => r.status === 'fulfilled' && r.value.success);

  console.log(`\n\n✅ Completed ${successful.length}/${prompts.length} streams`);
}

async function errorHandlingExample() {
  console.log('\n🛡️ Error Handling Example');

  const openai = createClient();

  // Function with retry logic
  async function resilientStream(prompt, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`🔄 Attempt ${attempt} for: "${prompt.substring(0, 30)}..."`);

        const stream = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: prompt }],
          stream: true,
          max_tokens: 100,
          timeout: 10000  // 10s timeout for this example
        });

        let content = '';
        for await (const chunk of stream) {
          const delta = chunk.choices[0]?.delta?.content || '';
          if (delta) {
            content += delta;
            process.stdout.write(delta);
          }
        }

        console.log(`\n✅ Success on attempt ${attempt}`);
        return { content, attempts: attempt, success: true };

      } catch (error) {
        console.log(`\n⚠️  Attempt ${attempt} failed: ${error.message}`);
        
        if (attempt === maxRetries) {
          console.log('❌ All attempts failed');
          return { error: error.message, attempts: attempt, success: false };
        }

        // Exponential backoff
        const delay = Math.pow(2, attempt - 1) * 1000;
        console.log(`⏱️  Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  // Test with a normal prompt
  await resilientStream('What is Node.js?');
}

async function streamingWithFunctions() {
  console.log('\n🔧 Streaming with Function Calls');

  const openai = createClient();

  const tools = [
    {
      type: 'function',
      function: {
        name: 'get_current_time',
        description: 'Get the current time in a specific timezone',
        parameters: {
          type: 'object',
          properties: {
            timezone: { type: 'string', description: 'Timezone (e.g., UTC, EST, PST)' }
          },
          required: ['timezone']
        }
      }
    }
  ];

  try {
    const stream = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: 'What time is it in New York?' }
      ],
      tools: tools,
      stream: true
    });

    console.log('📞 Processing function call request...');
    
    let functionCall = null;
    let textContent = '';

    for await (const chunk of stream) {
      const choice = chunk.choices[0];
      
      if (choice?.delta?.content) {
        textContent += choice.delta.content;
        process.stdout.write(choice.delta.content);
      }

      if (choice?.delta?.tool_calls) {
        const toolCall = choice.delta.tool_calls[0];
        if (toolCall?.function) {
          functionCall = toolCall.function;
        }
      }
    }

    if (functionCall) {
      console.log(`\n🔧 Function called: ${functionCall.name}`);
      console.log(`📋 Arguments: ${functionCall.arguments}`);
      
      // Simulate function execution
      const args = JSON.parse(functionCall.arguments);
      const currentTime = new Date().toLocaleString('en-US', { 
        timeZone: args.timezone === 'EST' ? 'America/New_York' : 'UTC' 
      });
      console.log(`🕐 Current time in ${args.timezone}: ${currentTime}`);
    }

  } catch (error) {
    console.error(`❌ Function streaming error: ${error.message}`);
  }
}

async function checkStreamingMetrics() {
  console.log('\n📊 Checking Streaming Metrics');

  try {
    // Get performance metrics
    const perfResponse = await fetch('http://localhost:8080/metrics/performance');
    if (perfResponse.ok) {
      const perfData = await perfResponse.json();
      console.log(`⚡ Average TTFT: ${perfData.streaming?.avg_time_to_first_token_ms || 'N/A'}ms`);
      console.log(`🏃 Tokens per second: ${perfData.streaming?.avg_tokens_per_second || 'N/A'}`);
      console.log(`📈 Average latency: ${perfData.latency?.avg_ms || 'N/A'}ms`);
    }

    // Get recent traces
    const tracesResponse = await fetch('http://localhost:8080/traces?limit=5');
    if (tracesResponse.ok) {
      const traces = await tracesResponse.json();
      console.log(`\n📋 Recent traces:`);
      traces.slice(0, 3).forEach((trace, i) => {
        console.log(`  ${i + 1}. ${trace.trace_id} - ${trace.duration_ms}ms (${trace.total_tokens} tokens)`);
      });
    }

  } catch (error) {
    console.error('❌ Could not fetch streaming metrics');
  }
}

async function main() {
  if (!process.env.OPENAI_API_KEY) {
    console.error('❌ Please set OPENAI_API_KEY in .env file');
    process.exit(1);
  }

  console.log('🌊 Node.js Streaming + LLMTrace Examples');
  console.log('='.repeat(50));

  try {
    await basicStreamingExample();
    await concurrentStreamsExample();
    await errorHandlingExample();
    await streamingWithFunctions();
    
    // Give LLMTrace time to process
    await new Promise(resolve => setTimeout(resolve, 2000));
    await checkStreamingMetrics();

    console.log('\n✅ All streaming examples completed!');
    console.log('🔍 View detailed metrics: http://localhost:8080/metrics/performance');

  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
  }
}

main();