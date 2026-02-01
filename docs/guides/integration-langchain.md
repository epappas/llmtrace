# LangChain Integration Guide

This guide shows how to integrate LLMTrace with LangChain applications. LLMTrace works seamlessly with LangChain by configuring the underlying LLM clients to use the proxy.

## Installation

```bash
pip install langchain langchain-openai openai
```

## Basic LangChain Integration

### ChatOpenAI Integration

```python
from langchain_openai import ChatOpenAI
import os

# Configure ChatOpenAI to use LLMTrace proxy
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",  # LLMTrace proxy
    temperature=0.7
)

# Use normally - LLMTrace captures everything
response = llm.invoke("What is the capital of France?")
print(response.content)
```

### OpenAI Integration (Legacy)

```python
from langchain.llms import OpenAI

llm = OpenAI(
    model="gpt-3.5-turbo-instruct", 
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    temperature=0.7
)

response = llm("Tell me a joke")
print(response)
```

## Complete LangChain Application Examples

### Simple Q&A Chain

```python
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage
import os

# Set up LLM with LLMTrace
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

def ask_question(question: str) -> str:
    messages = [
        SystemMessage(content="You are a helpful AI assistant."),
        HumanMessage(content=question)
    ]
    response = llm.invoke(messages)
    return response.content

# Usage
answer = ask_question("Explain quantum computing in simple terms")
print(answer)
```

### RAG (Retrieval-Augmented Generation)

```python
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain.vectorstores import Chroma
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.schema import Document

# Configure LLM and embeddings with LLMTrace
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

embeddings = OpenAIEmbeddings(
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"  # Also proxy embeddings
)

# Sample documents
documents = [
    Document(page_content="LLMTrace is a security-aware observability tool for LLM applications."),
    Document(page_content="It provides prompt injection detection and PII scanning."),
    Document(page_content="LLMTrace acts as a transparent proxy between your app and LLM providers.")
]

# Create vector store
text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
texts = text_splitter.split_documents(documents)
vectorstore = Chroma.from_documents(texts, embeddings)

# Create RAG chain
qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever()
)

# Query the chain
query = "What security features does LLMTrace provide?"
result = qa_chain.run(query)
print(result)
```

### Conversational Memory

```python
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationChain

# Set up LLM with memory
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

memory = ConversationBufferMemory()
conversation = ConversationChain(
    llm=llm,
    memory=memory,
    verbose=True  # See the conversation history
)

# Have a conversation
print(conversation.predict(input="Hi, I'm John"))
print(conversation.predict(input="What's my name?"))
print(conversation.predict(input="Tell me about AI"))
```

### Sequential Chains

```python
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain, SequentialChain
from langchain.prompts import PromptTemplate

# Configure LLM
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

# First chain: Generate a story idea
story_prompt = PromptTemplate(
    input_variables=["genre"],
    template="Generate a creative {genre} story idea in 2-3 sentences."
)
story_chain = LLMChain(
    llm=llm,
    prompt=story_prompt,
    output_key="story_idea"
)

# Second chain: Create characters
character_prompt = PromptTemplate(
    input_variables=["story_idea"],
    template="Based on this story idea: {story_idea}\n\nCreate 3 interesting characters with brief descriptions."
)
character_chain = LLMChain(
    llm=llm,
    prompt=character_prompt,
    output_key="characters"
)

# Sequential chain
sequential_chain = SequentialChain(
    chains=[story_chain, character_chain],
    input_variables=["genre"],
    output_variables=["story_idea", "characters"]
)

# Execute the chain
result = sequential_chain({"genre": "science fiction"})
print("Story Idea:", result["story_idea"])
print("\nCharacters:", result["characters"])
```

## Streaming Support

### Streaming Responses

```python
from langchain_openai import ChatOpenAI
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.schema import HumanMessage

# Configure streaming LLM
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    streaming=True,
    callbacks=[StreamingStdOutCallbackHandler()]  # Print to stdout as it streams
)

# Stream a response
message = HumanMessage(content="Write a short story about a robot discovering emotions.")
response = llm.invoke([message])
```

### Custom Streaming Callback

```python
from langchain.callbacks.base import BaseCallbackHandler
from typing import Any, Dict

class CustomStreamingHandler(BaseCallbackHandler):
    """Custom handler to process streaming tokens."""
    
    def __init__(self):
        self.tokens = []
        self.total_tokens = 0
    
    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """Called when a new token is generated."""
        self.tokens.append(token)
        self.total_tokens += 1
        print(f"Token {self.total_tokens}: {token}", end="", flush=True)
    
    def on_llm_end(self, response, **kwargs: Any) -> None:
        """Called when LLM finishes."""
        print(f"\n\n✅ Streaming complete. Total tokens: {self.total_tokens}")

# Use custom handler
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    streaming=True,
    callbacks=[CustomStreamingHandler()]
)
```

## LangChain Agents

### Tool-Using Agent

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_openai_functions_agent, AgentExecutor
from langchain.tools import tool
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
import requests

# Configure LLM
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

# Define tools
@tool
def get_weather(location: str) -> str:
    """Get current weather for a location."""
    # Mock weather API call
    return f"The weather in {location} is sunny and 72°F."

@tool 
def calculate_math(expression: str) -> str:
    """Calculate a mathematical expression."""
    try:
        result = eval(expression)
        return f"The result is {result}"
    except:
        return "Invalid mathematical expression"

# Create agent
tools = [get_weather, calculate_math]

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant with access to tools."),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

agent = create_openai_functions_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Use the agent
result = agent_executor.invoke({
    "input": "What's the weather in New York and what's 15 * 23?"
})
print(result["output"])
```

### ReAct Agent

```python
from langchain.agents import create_react_agent, AgentExecutor
from langchain.tools import Tool
from langchain.prompts import PromptTemplate

# Create a simple search tool
def search_tool(query: str) -> str:
    """A mock search function."""
    search_results = {
        "python": "Python is a high-level programming language.",
        "llm": "Large Language Models are AI models trained on text data.",
        "langchain": "LangChain is a framework for building LLM applications."
    }
    return search_results.get(query.lower(), f"No results found for '{query}'")

tools = [
    Tool(
        name="Search",
        func=search_tool,
        description="Search for information about programming topics"
    )
]

# ReAct prompt template
prompt = PromptTemplate.from_template("""
You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Question: {input}
{agent_scratchpad}
""")

# Create agent
agent = create_react_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Use the agent
result = agent_executor.invoke({
    "input": "What is LangChain and how does it relate to LLMs?"
})
```

## Multi-Modal Capabilities

### Vision/Image Analysis

```python
from langchain_openai import ChatOpenAI
from langchain.schema.messages import HumanMessage, ImagePromptTemplate

# Configure vision-capable model
llm = ChatOpenAI(
    model="gpt-4-vision-preview",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    max_tokens=300
)

# Analyze an image
def analyze_image(image_url: str, question: str) -> str:
    message = HumanMessage(
        content=[
            {"type": "text", "text": question},
            {"type": "image_url", "image_url": {"url": image_url}}
        ]
    )
    response = llm.invoke([message])
    return response.content

# Usage
image_url = "https://upload.wikimedia.org/wikipedia/commons/thumb/d/dd/Gfp-wisconsin-madison-the-nature-boardwalk.jpg/2560px-Gfp-wisconsin-madison-the-nature-boardwalk.jpg"
description = analyze_image(image_url, "What do you see in this image?")
print(description)
```

## LangChain Expression Language (LCEL)

### Chain Composition with LCEL

```python
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import StrOutputParser

# Configure components
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

prompt = ChatPromptTemplate.from_template(
    "Tell me a {adjective} joke about {topic}"
)

output_parser = StrOutputParser()

# Create chain using LCEL
chain = prompt | llm | output_parser

# Use the chain
result = chain.invoke({
    "adjective": "funny",
    "topic": "programming"
})
print(result)
```

### Parallel Processing

```python
from langchain.schema.runnable import RunnableParallel, RunnableLambda

# Define parallel processing functions
def make_uppercase(text: str) -> str:
    return text.upper()

def count_words(text: str) -> int:
    return len(text.split())

def get_sentiment(text: str) -> str:
    # Mock sentiment analysis
    return "positive" if "good" in text.lower() else "neutral"

# Create parallel chain
analysis_chain = RunnableParallel(
    original=RunnableLambda(lambda x: x),
    uppercase=RunnableLambda(make_uppercase),
    word_count=RunnableLambda(count_words),
    sentiment=RunnableLambda(get_sentiment)
)

# Create full pipeline
full_chain = prompt | llm | analysis_chain

# Execute
result = full_chain.invoke({
    "adjective": "good",
    "topic": "artificial intelligence"
})

print(f"Original: {result['original']}")
print(f"Uppercase: {result['uppercase']}")
print(f"Word count: {result['word_count']}")
print(f"Sentiment: {result['sentiment']}")
```

## Multi-Tenant Configuration

### Per-Customer LLM Configuration

```python
from langchain_openai import ChatOpenAI
from typing import Dict
import os

class MultiTenantLLMManager:
    def __init__(self):
        self.llms: Dict[str, ChatOpenAI] = {}
    
    def get_llm_for_customer(self, customer_id: str) -> ChatOpenAI:
        if customer_id not in self.llms:
            self.llms[customer_id] = ChatOpenAI(
                model="gpt-4",
                openai_api_key=os.getenv("OPENAI_API_KEY"),
                openai_api_base="http://localhost:8080/v1",
                default_headers={
                    "X-LLMTrace-Tenant-ID": customer_id,
                    "X-LLMTrace-Customer": customer_id
                }
            )
        return self.llms[customer_id]

# Usage
manager = MultiTenantLLMManager()

# Customer A's request
customer_a_llm = manager.get_llm_for_customer("customer_a")
response_a = customer_a_llm.invoke("Hello from customer A")

# Customer B's request  
customer_b_llm = manager.get_llm_for_customer("customer_b")
response_b = customer_b_llm.invoke("Hello from customer B")

# Each customer's requests are isolated in LLMTrace
```

## Error Handling and Resilience

### Retry Logic

```python
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def resilient_llm_call(llm: ChatOpenAI, message: str) -> str:
    """Make LLM call with retry logic."""
    try:
        response = llm.invoke(message)
        return response.content
    except Exception as e:
        logger.warning(f"LLM call failed: {e}")
        raise

# Configure LLM
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    request_timeout=30  # 30 second timeout
)

# Use with retry
try:
    result = resilient_llm_call(llm, "What is machine learning?")
    print(result)
except Exception as e:
    print(f"Failed after retries: {e}")
```

### Fallback to Direct API

```python
from langchain_openai import ChatOpenAI
import requests

def create_resilient_llm() -> ChatOpenAI:
    """Create LLM with fallback logic."""
    
    # First, try LLMTrace proxy
    try:
        response = requests.get("http://localhost:8080/health", timeout=2)
        if response.status_code == 200:
            print("✅ Using LLMTrace proxy")
            return ChatOpenAI(
                model="gpt-4",
                openai_api_key=os.getenv("OPENAI_API_KEY"),
                openai_api_base="http://localhost:8080/v1"
            )
    except requests.RequestException:
        pass
    
    # Fallback to direct OpenAI
    print("⚠️ LLMTrace unavailable, using direct OpenAI API")
    return ChatOpenAI(
        model="gpt-4",
        openai_api_key=os.getenv("OPENAI_API_KEY")
        # No openai_api_base = uses default OpenAI endpoint
    )

# Usage
llm = create_resilient_llm()
response = llm.invoke("Hello!")
```

## Monitoring Integration

### Custom Callbacks for Observability

```python
from langchain.callbacks.base import BaseCallbackHandler
from typing import Any, Dict, List
import requests
import json
import time

class LLMTraceMonitoringCallback(BaseCallbackHandler):
    """Custom callback to enhance LLMTrace monitoring."""
    
    def __init__(self, llmtrace_url: str = "http://localhost:8080"):
        self.llmtrace_url = llmtrace_url
        self.start_time = None
        
    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs) -> None:
        """Called when LLM starts."""
        self.start_time = time.time()
        print(f"🚀 LLM started with {len(prompts)} prompts")
        
    def on_llm_end(self, response, **kwargs) -> None:
        """Called when LLM ends."""
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"✅ LLM completed in {duration:.2f}s")
            
            # Check for security findings
            try:
                findings_response = requests.get(f"{self.llmtrace_url}/security/findings", timeout=5)
                if findings_response.status_code == 200:
                    findings = findings_response.json()
                    recent_findings = [f for f in findings if time.time() - f.get('timestamp', 0) < 60]
                    if recent_findings:
                        print(f"⚠️ {len(recent_findings)} security findings in last minute")
            except:
                pass
                
    def on_llm_error(self, error: BaseException, **kwargs) -> None:
        """Called when LLM encounters an error."""
        print(f"❌ LLM error: {error}")

# Use with LangChain
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1",
    callbacks=[LLMTraceMonitoringCallback()]
)

response = llm.invoke("Tell me about Python programming")
```

## Best Practices

### Configuration Management

```python
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
import os

@dataclass
class LLMConfig:
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 1000
    llmtrace_url: str = "http://localhost:8080"
    
class ConfigurableLLMFactory:
    @staticmethod
    def create_llm(config: LLMConfig) -> ChatOpenAI:
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            openai_api_base=f"{config.llmtrace_url}/v1"
        )

# Usage
config = LLMConfig(
    model="gpt-4",
    temperature=0.1,  # More focused responses
    max_tokens=500
)

llm = ConfigurableLLMFactory.create_llm(config)
```

### Structured Output

```python
from langchain_openai import ChatOpenAI
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate
from pydantic import BaseModel, Field
from typing import List

# Define output structure
class MovieRecommendation(BaseModel):
    title: str = Field(description="Movie title")
    genre: str = Field(description="Primary genre")
    year: int = Field(description="Release year")
    rating: float = Field(description="IMDb rating out of 10")
    reason: str = Field(description="Why this movie is recommended")

class MovieRecommendations(BaseModel):
    movies: List[MovieRecommendation] = Field(description="List of movie recommendations")

# Set up parser and prompt
parser = PydanticOutputParser(pydantic_object=MovieRecommendations)

prompt = PromptTemplate(
    template="Recommend {num_movies} movies based on the user's preference for {preference}.\n{format_instructions}\n",
    input_variables=["num_movies", "preference"],
    partial_variables={"format_instructions": parser.get_format_instructions()}
)

# Configure LLM
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    openai_api_base="http://localhost:8080/v1"
)

# Create chain
chain = prompt | llm | parser

# Use chain
result = chain.invoke({
    "num_movies": 3,
    "preference": "sci-fi movies with AI themes"
})

for movie in result.movies:
    print(f"📽️ {movie.title} ({movie.year}) - {movie.genre}")
    print(f"   Rating: {movie.rating}/10")
    print(f"   Reason: {movie.reason}\n")
```

## Troubleshooting

### Common Issues

**SSL/TLS Errors:**
```python
# If using HTTPS with self-signed certificates
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

llm = ChatOpenAI(
    openai_api_base="https://localhost:8443/v1",
    # ... other config
)
```

**Token Limit Errors:**
```python
# Handle token limit gracefully
from langchain.text_splitter import RecursiveCharacterTextSplitter

def safe_llm_call(llm, text: str, max_tokens: int = 3000) -> str:
    """Split long text and process in chunks."""
    
    if len(text) <= max_tokens:
        return llm.invoke(text).content
    
    # Split text into chunks
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=max_tokens,
        chunk_overlap=200
    )
    chunks = splitter.split_text(text)
    
    # Process each chunk
    results = []
    for chunk in chunks:
        response = llm.invoke(f"Summarize this text: {chunk}")
        results.append(response.content)
    
    return "\n".join(results)
```

**Connection Issues:**
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure requests session with retries
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Use session for health checks
def check_llmtrace_health():
    try:
        response = session.get("http://localhost:8080/health", timeout=5)
        return response.status_code == 200
    except:
        return False
```

## Next Steps

- **[OpenAI SDK Integration](integration-openai.md)** — Direct SDK usage patterns
- **[Python SDK](python-sdk.md)** — Native instrumentation approach
- **[Dashboard Usage](dashboard.md)** — Monitor your LangChain applications  
- **[Custom Policies](custom-policies.md)** — Configure security for your use cases

**Need help?** Check the [LangChain documentation](https://python.langchain.com/docs/get_started/introduction) and [LLMTrace troubleshooting](../deployment/troubleshooting.md).