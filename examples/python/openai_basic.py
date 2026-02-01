#!/usr/bin/env python3
"""
Basic OpenAI SDK integration with LLMTrace

This example shows the minimal change needed to add observability:
just change base_url to point at LLMTrace proxy.
"""

import openai
import os
import time

def main():
    # Create OpenAI client pointing at LLMTrace proxy
    client = openai.OpenAI(
        base_url="http://localhost:8080/v1",  # LLMTrace proxy
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    print("🚀 Making OpenAI request through LLMTrace...")
    
    try:
        # Make a simple chat completion
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful AI assistant."},
                {"role": "user", "content": "Explain quantum computing in simple terms"}
            ],
            temperature=0.7,
            max_tokens=200
        )
        
        print("✅ Response received!")
        print(f"📝 Content: {response.choices[0].message.content}")
        print(f"📊 Tokens: {response.usage.total_tokens} ({response.usage.prompt_tokens} + {response.usage.completion_tokens})")
        
        # Give LLMTrace time to process the trace
        time.sleep(1)
        
        # Check if traces were captured
        import requests
        traces_response = requests.get("http://localhost:8080/traces")
        if traces_response.status_code == 200:
            traces = traces_response.json()
            print(f"🔍 Found {len(traces)} traces in LLMTrace")
            
            if traces:
                latest = traces[0]
                print(f"📈 Latest trace: {latest['trace_id']} ({latest['duration_ms']}ms)")
        
    except openai.APIError as e:
        print(f"❌ OpenAI API error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    main()