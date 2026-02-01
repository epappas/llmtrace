#!/usr/bin/env python3
"""
Async OpenAI example with LLMTrace

Demonstrates async patterns, concurrent requests, and error handling
for high-performance applications.
"""

import asyncio
import openai
import os
import time
from typing import List, Dict, Any

async def create_async_client() -> openai.AsyncOpenAI:
    """Create async OpenAI client configured for LLMTrace."""
    return openai.AsyncOpenAI(
        base_url="http://localhost:8080/v1",
        api_key=os.getenv("OPENAI_API_KEY")
    )

async def single_async_request(client: openai.AsyncOpenAI, prompt: str) -> Dict[str, Any]:
    """Make a single async request."""
    try:
        start_time = time.time()
        
        response = await client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=100
        )
        
        duration = time.time() - start_time
        
        return {
            "prompt": prompt,
            "response": response.choices[0].message.content,
            "tokens": response.usage.total_tokens,
            "duration": duration,
            "success": True
        }
        
    except Exception as e:
        return {
            "prompt": prompt,
            "error": str(e),
            "success": False
        }

async def concurrent_requests_example():
    """Run multiple requests concurrently."""
    print("🚀 Concurrent Requests Example")
    
    client = await create_async_client()
    
    # Multiple prompts to process concurrently
    prompts = [
        "Explain machine learning in one sentence",
        "What is the capital of Japan?",
        "How do you make coffee?",
        "What's the largest planet?",
        "Define artificial intelligence"
    ]
    
    print(f"📤 Sending {len(prompts)} concurrent requests...")
    start_time = time.time()
    
    # Run all requests concurrently
    tasks = [single_async_request(client, prompt) for prompt in prompts]
    results = await asyncio.gather(*tasks)
    
    total_time = time.time() - start_time
    successful = [r for r in results if r["success"]]
    
    print(f"✅ Completed {len(successful)}/{len(prompts)} requests in {total_time:.1f}s")
    print(f"📊 Average latency: {total_time/len(prompts):.1f}s per request")
    
    # Show results
    for i, result in enumerate(results, 1):
        if result["success"]:
            print(f"  {i}. ✅ {result['tokens']} tokens in {result['duration']:.1f}s")
            print(f"     📝 {result['response'][:60]}...")
        else:
            print(f"  {i}. ❌ Error: {result['error']}")
    
    await client.close()
    return results

async def streaming_async_example():
    """Async streaming example."""
    print("\n🌊 Async Streaming Example")
    
    client = await create_async_client()
    
    print("📝 Generating story asynchronously...")
    
    try:
        stream = await client.chat.completions.create(
            model="gpt-4",
            messages=[{
                "role": "user", 
                "content": "Write a haiku about programming"
            }],
            stream=True,
            max_tokens=100
        )
        
        content_parts = []
        async for chunk in stream:
            if chunk.choices[0].delta.content is not None:
                content = chunk.choices[0].delta.content
                content_parts.append(content)
                print(content, end="", flush=True)
        
        print(f"\n✅ Streaming complete! Generated {len(''.join(content_parts))} characters")
        
    except Exception as e:
        print(f"❌ Streaming error: {e}")
    
    await client.close()

async def batch_processing_example():
    """Process a batch of items with rate limiting."""
    print("\n📦 Batch Processing with Rate Limiting")
    
    client = await create_async_client()
    
    # Simulate a batch of user questions
    questions = [
        "How do I learn Python?",
        "What is Docker?", 
        "Explain REST APIs",
        "What is cloud computing?",
        "How does encryption work?",
        "What is a database?",
        "Explain version control",
        "What is DevOps?"
    ]
    
    async def process_with_delay(prompt: str, delay: float) -> Dict[str, Any]:
        """Process with a delay to simulate rate limiting."""
        await asyncio.sleep(delay)
        return await single_async_request(client, prompt)
    
    print(f"⚙️ Processing {len(questions)} questions with 0.5s delays...")
    
    # Process with staggered delays
    tasks = [
        process_with_delay(question, i * 0.5) 
        for i, question in enumerate(questions)
    ]
    
    start_time = time.time()
    results = await asyncio.gather(*tasks)
    total_time = time.time() - start_time
    
    successful = [r for r in results if r["success"]]
    total_tokens = sum(r.get("tokens", 0) for r in successful)
    
    print(f"✅ Processed {len(successful)} questions in {total_time:.1f}s")
    print(f"📊 Total tokens: {total_tokens}")
    print(f"⚡ Throughput: {len(successful)/total_time:.1f} requests/second")
    
    await client.close()
    return results

async def error_handling_example():
    """Demonstrate error handling patterns."""
    print("\n🛡️ Error Handling Example")
    
    client = await create_async_client()
    
    async def resilient_request(prompt: str, max_retries: int = 3) -> Dict[str, Any]:
        """Make request with retry logic."""
        for attempt in range(max_retries):
            try:
                response = await client.chat.completions.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}],
                    timeout=10.0  # 10 second timeout
                )
                
                return {
                    "prompt": prompt,
                    "response": response.choices[0].message.content,
                    "attempt": attempt + 1,
                    "success": True
                }
                
            except openai.APITimeoutError:
                print(f"⏱️ Timeout on attempt {attempt + 1}")
                if attempt == max_retries - 1:
                    return {"prompt": prompt, "error": "Timeout after retries", "success": False}
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except openai.APIError as e:
                print(f"❌ API error on attempt {attempt + 1}: {e}")
                return {"prompt": prompt, "error": str(e), "success": False}
            
            except Exception as e:
                print(f"❌ Unexpected error: {e}")
                return {"prompt": prompt, "error": str(e), "success": False}
    
    # Test with a challenging prompt
    result = await resilient_request("Explain quantum computing in simple terms")
    
    if result["success"]:
        print(f"✅ Success on attempt {result['attempt']}")
        print(f"📝 Response: {result['response'][:100]}...")
    else:
        print(f"❌ Failed: {result['error']}")
    
    await client.close()

async def check_traces_async():
    """Check LLMTrace data asynchronously."""
    import aiohttp
    
    print("\n📊 Checking LLMTrace Data")
    
    try:
        async with aiohttp.ClientSession() as session:
            # Get traces
            async with session.get("http://localhost:8080/traces") as resp:
                if resp.status == 200:
                    traces = await resp.json()
                    print(f"📈 Found {len(traces)} traces")
                    
                    # Calculate stats
                    if traces:
                        total_tokens = sum(t.get('total_tokens', 0) for t in traces)
                        avg_duration = sum(t.get('duration_ms', 0) for t in traces) / len(traces)
                        print(f"📊 Total tokens: {total_tokens}")
                        print(f"⏱️ Average duration: {avg_duration:.0f}ms")
            
            # Get security findings
            async with session.get("http://localhost:8080/security/findings") as resp:
                if resp.status == 200:
                    findings = await resp.json()
                    if findings:
                        print(f"⚠️ Security findings: {len(findings)}")
                    else:
                        print("✅ No security issues detected")
    
    except Exception as e:
        print(f"❌ Could not check LLMTrace: {e}")

async def main():
    """Run all async examples."""
    print("⚡ Async OpenAI + LLMTrace Examples")
    print("=" * 50)
    
    try:
        await concurrent_requests_example()
        await streaming_async_example()
        await batch_processing_example()
        await error_handling_example()
        
        # Give LLMTrace time to process
        await asyncio.sleep(2)
        await check_traces_async()
        
        print("\n✅ All async examples completed!")
        print("🔍 View detailed traces: http://localhost:8080/traces")
        
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    asyncio.run(main())