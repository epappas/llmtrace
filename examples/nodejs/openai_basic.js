#!/usr/bin/env node

/**
 * Basic OpenAI SDK integration with LLMTrace
 * 
 * This example shows the minimal change needed to add observability:
 * just change baseURL to point at LLMTrace proxy.
 */

import OpenAI from 'openai';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  // Create OpenAI client pointing at LLMTrace proxy
  const openai = new OpenAI({
    baseURL: 'http://localhost:8080/v1',  // LLMTrace proxy
    apiKey: process.env.OPENAI_API_KEY
  });

  console.log('🚀 Making OpenAI request through LLMTrace...');

  try {
    // Make a simple chat completion
    const response = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'You are a helpful AI assistant.' },
        { role: 'user', content: 'Explain machine learning in simple terms' }
      ],
      temperature: 0.7,
      max_tokens: 200
    });

    console.log('✅ Response received!');
    console.log(`📝 Content: ${response.choices[0].message.content}`);
    console.log(`📊 Tokens: ${response.usage.total_tokens} (${response.usage.prompt_tokens} + ${response.usage.completion_tokens})`);

    // Give LLMTrace time to process the trace
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Check if traces were captured
    const tracesResponse = await fetch('http://localhost:8080/traces');
    if (tracesResponse.ok) {
      const traces = await tracesResponse.json();
      console.log(`🔍 Found ${traces.length} traces in LLMTrace`);
      
      if (traces.length > 0) {
        const latest = traces[0];
        console.log(`📈 Latest trace: ${latest.trace_id} (${latest.duration_ms}ms)`);
      }
    }

  } catch (error) {
    if (error instanceof OpenAI.APIError) {
      console.error(`❌ OpenAI API error: ${error.message}`);
      console.error(`Status: ${error.status}`);
    } else {
      console.error(`❌ Unexpected error: ${error.message}`);
    }
  }
}

// Function calling example
async function functionCallingExample() {
  console.log('\n🔧 Function Calling Example');
  
  const openai = new OpenAI({
    baseURL: 'http://localhost:8080/v1',
    apiKey: process.env.OPENAI_API_KEY
  });

  const tools = [
    {
      type: 'function',
      function: {
        name: 'calculate_tip',
        description: 'Calculate tip amount for a bill',
        parameters: {
          type: 'object',
          properties: {
            bill_amount: { type: 'number', description: 'The bill amount' },
            tip_percentage: { type: 'number', description: 'Tip percentage (0-100)' }
          },
          required: ['bill_amount', 'tip_percentage']
        }
      }
    }
  ];

  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: 'Calculate a 18% tip on a $85 bill' }
      ],
      tools: tools,
      tool_choice: 'auto'
    });

    const message = response.choices[0].message;
    if (message.tool_calls) {
      const toolCall = message.tool_calls[0];
      console.log(`🔧 Function called: ${toolCall.function.name}`);
      console.log(`📋 Arguments: ${toolCall.function.arguments}`);
      
      // Simulate function execution
      const args = JSON.parse(toolCall.function.arguments);
      const tipAmount = (args.bill_amount * args.tip_percentage) / 100;
      console.log(`💰 Calculated tip: $${tipAmount.toFixed(2)}`);
    } else {
      console.log(`💬 Response: ${message.content}`);
    }

  } catch (error) {
    console.error(`❌ Function calling error: ${error.message}`);
  }
}

// Multi-turn conversation example
async function conversationExample() {
  console.log('\n💭 Multi-turn Conversation');
  
  const openai = new OpenAI({
    baseURL: 'http://localhost:8080/v1',
    apiKey: process.env.OPENAI_API_KEY
  });

  const messages = [
    { role: 'system', content: 'You are a helpful coding assistant.' }
  ];

  const userInputs = [
    'I want to learn web development. Where should I start?',
    'What about JavaScript frameworks?',
    'Can you explain what React components are?'
  ];

  for (const [index, userInput] of userInputs.entries()) {
    console.log(`\n👤 User: ${userInput}`);
    
    messages.push({ role: 'user', content: userInput });

    try {
      const response = await openai.chat.completions.create({
        model: 'gpt-4',
        messages: messages,
        max_tokens: 150
      });

      const assistantReply = response.choices[0].message.content;
      console.log(`🤖 Assistant: ${assistantReply}`);
      
      messages.push({ role: 'assistant', content: assistantReply });

    } catch (error) {
      console.error(`❌ Conversation error: ${error.message}`);
      break;
    }
  }
}

// Check security and cost metrics
async function checkMetrics() {
  console.log('\n📊 Checking LLMTrace Metrics');

  try {
    // Check security findings
    const findingsResponse = await fetch('http://localhost:8080/security/findings');
    if (findingsResponse.ok) {
      const findings = await findingsResponse.json();
      if (findings.length > 0) {
        console.log(`⚠️  Security findings: ${findings.length}`);
        findings.slice(0, 2).forEach(finding => {
          console.log(`  - ${finding.finding_type}: ${finding.title}`);
        });
      } else {
        console.log('✅ No security issues detected');
      }
    }

    // Check cost metrics
    const costResponse = await fetch('http://localhost:8080/metrics/costs');
    if (costResponse.ok) {
      const costData = await costResponse.json();
      console.log(`💰 Total cost: $${costData.total_cost_usd || 0}`);
      console.log(`📊 Total tokens: ${costData.total_tokens || 0}`);
    }

  } catch (error) {
    console.error('❌ Could not fetch metrics. Is LLMTrace running?');
  }
}

// Main execution
async function runAll() {
  if (!process.env.OPENAI_API_KEY) {
    console.error('❌ Please set OPENAI_API_KEY environment variable');
    process.exit(1);
  }

  console.log('🟢 Node.js + LLMTrace Integration Examples');
  console.log('='.repeat(50));

  try {
    await main();
    await functionCallingExample();
    await conversationExample();
    
    // Give LLMTrace time to process
    await new Promise(resolve => setTimeout(resolve, 2000));
    await checkMetrics();

    console.log('\n✅ All examples completed!');
    console.log('🔍 View traces at: http://localhost:8080/traces');

  } catch (error) {
    console.error(`❌ Error running examples: ${error.message}`);
  }
}

runAll();