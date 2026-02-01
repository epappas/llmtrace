#!/usr/bin/env python3
"""
OpenAI streaming example with LLMTrace

Demonstrates streaming responses and custom token counting.
LLMTrace captures streaming metrics like time-to-first-token.
"""

import openai
import os
import time
from typing import Generator

def stream_chat_completion(client: openai.OpenAI, messages: list) -> Generator[str, None, None]:
    """Stream chat completion and yield tokens."""
    
    stream = client.chat.completions.create(
        model="gpt-4",
        messages=messages,
        stream=True,
        max_tokens=300
    )
    
    for chunk in stream:
        if chunk.choices[0].delta.content is not None:
            yield chunk.choices[0].delta.content

def main():
    # Create streaming OpenAI client
    client = openai.OpenAI(
        base_url="http://localhost:8080/v1",
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    messages = [
        {"role": "system", "content": "You are a creative writer."},
        {"role": "user", "content": "Write a short story about a robot discovering emotions for the first time."}
    ]
    
    print("🚀 Starting streaming chat completion...")
    print("📝 Story:")
    print("-" * 50)
    
    start_time = time.time()
    first_token_time = None
    token_count = 0
    
    try:
        for token in stream_chat_completion(client, messages):
            if first_token_time is None:
                first_token_time = time.time()
                ttft = (first_token_time - start_time) * 1000
                print(f"\n⚡ Time to first token: {ttft:.0f}ms\n")
            
            print(token, end="", flush=True)
            token_count += 1
            
            # Small delay to see streaming effect
            time.sleep(0.01)
        
        total_time = time.time() - start_time
        tokens_per_second = token_count / total_time if total_time > 0 else 0
        
        print(f"\n\n✅ Streaming complete!")
        print(f"📊 Stats: {token_count} tokens in {total_time:.1f}s ({tokens_per_second:.1f} tok/s)")
        
        # Check LLMTrace for streaming metrics
        time.sleep(1)
        
        import requests
        traces = requests.get("http://localhost:8080/traces").json()
        if traces:
            latest = traces[0]
            print(f"🔍 LLMTrace captured: {latest['trace_id']}")
            print(f"📈 Total duration: {latest['duration_ms']}ms")
            # LLMTrace captures TTFT and streaming metrics automatically
            
    except openai.APIError as e:
        print(f"❌ OpenAI API error: {e}")
    except KeyboardInterrupt:
        print(f"\n⏹️ Streaming interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def demo_function_calling():
    """Demonstrate function calling with streaming."""
    
    client = openai.OpenAI(
        base_url="http://localhost:8080/v1",
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather for a location",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City name"},
                        "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                    },
                    "required": ["location"]
                }
            }
        }
    ]
    
    print("\n🌤️ Function calling example...")
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "What's the weather in Paris?"}],
        tools=tools,
        tool_choice="auto"
    )
    
    message = response.choices[0].message
    if message.tool_calls:
        print(f"🔧 Function called: {message.tool_calls[0].function.name}")
        print(f"📋 Arguments: {message.tool_calls[0].function.arguments}")
    else:
        print(f"💬 Response: {message.content}")

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    main()
    demo_function_calling()