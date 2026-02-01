#!/usr/bin/env python3
"""
LangChain integration with LLMTrace

Shows how to use LLMTrace with LangChain for RAG, agents, and chains.
All LLM calls are automatically traced with full context.
"""

import os
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain, ConversationChain
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain.schema import HumanMessage, SystemMessage

def create_llm():
    """Create LangChain LLM configured for LLMTrace."""
    return ChatOpenAI(
        model="gpt-4",
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        openai_api_base="http://localhost:8080/v1",  # LLMTrace proxy
        temperature=0.7
    )

def basic_chain_example():
    """Simple prompt template chain."""
    print("🔗 Basic Chain Example")
    
    llm = create_llm()
    
    prompt = PromptTemplate(
        input_variables=["product"],
        template="Write a creative marketing slogan for {product}."
    )
    
    chain = LLMChain(llm=llm, prompt=prompt)
    
    result = chain.run(product="sustainable coffee pods")
    print(f"📢 Slogan: {result}")
    return result

def conversation_with_memory():
    """Conversation chain with memory."""
    print("\n💭 Conversation with Memory")
    
    llm = create_llm()
    memory = ConversationBufferMemory()
    conversation = ConversationChain(llm=llm, memory=memory, verbose=True)
    
    # Multi-turn conversation - each turn gets traced
    responses = []
    
    print("👋 Starting conversation...")
    response1 = conversation.predict(input="Hi, I'm building a Python web app. What framework should I use?")
    responses.append(response1)
    print(f"🤖: {response1}")
    
    response2 = conversation.predict(input="What about for machine learning integration?")  
    responses.append(response2)
    print(f"🤖: {response2}")
    
    response3 = conversation.predict(input="Can you remember what type of app I'm building?")
    responses.append(response3)
    print(f"🤖: {response3}")
    
    return responses

def simple_rag_example():
    """Simple RAG without external vector store."""
    print("\n📚 Simple RAG Example")
    
    llm = create_llm()
    
    # Mock knowledge base
    knowledge = """
    LLMTrace is a security-aware observability tool for LLM applications.
    It provides prompt injection detection, PII scanning, and cost tracking.
    LLMTrace acts as a transparent proxy between your app and LLM providers.
    It supports OpenAI, Anthropic, and other OpenAI-compatible APIs.
    """
    
    prompt = ChatPromptTemplate.from_template("""
    Context: {context}
    
    Question: {question}
    
    Answer the question based only on the provided context.
    """)
    
    chain = prompt | llm
    
    question = "What security features does LLMTrace provide?"
    result = chain.invoke({"context": knowledge, "question": question})
    
    print(f"❓ Question: {question}")
    print(f"💡 Answer: {result.content}")
    return result.content

def multi_step_analysis():
    """Multi-step analysis chain."""
    print("\n🔬 Multi-Step Analysis")
    
    llm = create_llm()
    
    # Step 1: Analyze the topic
    analysis_prompt = PromptTemplate(
        input_variables=["topic"],
        template="Analyze this topic and identify 3 key aspects to explore: {topic}"
    )
    analysis_chain = LLMChain(llm=llm, prompt=analysis_prompt)
    
    # Step 2: Deep dive into one aspect
    deepdive_prompt = PromptTemplate(
        input_variables=["aspects", "topic"],
        template="""
        Based on these key aspects of {topic}:
        {aspects}
        
        Choose the most interesting aspect and provide a detailed explanation.
        """
    )
    deepdive_chain = LLMChain(llm=llm, prompt=deepdive_prompt)
    
    topic = "Artificial Intelligence in Healthcare"
    
    # Execute multi-step analysis - each step gets its own trace
    print(f"🎯 Analyzing: {topic}")
    
    aspects = analysis_chain.run(topic=topic)
    print(f"📋 Key aspects: {aspects}")
    
    deep_analysis = deepdive_chain.run(aspects=aspects, topic=topic)
    print(f"🔍 Deep dive: {deep_analysis}")
    
    return {"aspects": aspects, "deep_analysis": deep_analysis}

def check_traces():
    """Check traces captured by LLMTrace."""
    import requests
    import time
    
    time.sleep(1)  # Give LLMTrace time to process
    
    try:
        response = requests.get("http://localhost:8080/traces")
        if response.status_code == 200:
            traces = response.json()
            print(f"\n📈 LLMTrace captured {len(traces)} traces")
            
            # Show latest traces
            for i, trace in enumerate(traces[:3]):
                print(f"  {i+1}. {trace['trace_id']} - {trace['model_name']} ({trace['duration_ms']}ms)")
            
            # Check for security findings
            findings_response = requests.get("http://localhost:8080/security/findings")
            if findings_response.status_code == 200:
                findings = findings_response.json()
                if findings:
                    print(f"⚠️ Security findings: {len(findings)}")
                else:
                    print("✅ No security findings")
        else:
            print(f"❌ Could not connect to LLMTrace (HTTP {response.status_code})")
    except requests.RequestException:
        print("❌ LLMTrace not reachable. Is it running on localhost:8080?")

def main():
    """Run all LangChain examples."""
    print("🦜 LangChain + LLMTrace Integration Examples")
    print("=" * 50)
    
    try:
        # Run examples
        basic_chain_example()
        conversation_with_memory()
        simple_rag_example()
        multi_step_analysis()
        
        # Check captured traces
        check_traces()
        
        print("\n✅ All examples completed!")
        print("🔍 View traces at: http://localhost:8080/traces")
        print("🛡️ Security findings: http://localhost:8080/security/findings")
        
    except Exception as e:
        print(f"❌ Error running examples: {e}")
        print("💡 Make sure LLMTrace is running and OPENAI_API_KEY is set")

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    main()