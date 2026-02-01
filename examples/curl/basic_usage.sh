#!/bin/bash

# Basic LLMTrace usage with curl
# Demonstrates: sending requests, checking traces, viewing metrics

set -e  # Exit on error

LLMTRACE_URL="http://localhost:8080"
OPENAI_API_KEY="${OPENAI_API_KEY}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 LLMTrace Basic Usage Demo${NC}"
echo "=================================="

# Check if API key is set
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}❌ Please set OPENAI_API_KEY environment variable${NC}"
    exit 1
fi

# Function to check if LLMTrace is running
check_llmtrace() {
    echo -e "${BLUE}🏥 Checking LLMTrace health...${NC}"
    
    if curl -s -f "$LLMTRACE_URL/health" > /dev/null; then
        echo -e "${GREEN}✅ LLMTrace is healthy${NC}"
        curl -s "$LLMTRACE_URL/health" | jq
    else
        echo -e "${RED}❌ LLMTrace is not reachable at $LLMTRACE_URL${NC}"
        echo "Please start LLMTrace: docker compose up -d"
        exit 1
    fi
}

# Function to send a chat request
send_chat_request() {
    echo -e "\n${BLUE}💬 Sending chat completion request...${NC}"
    
    local prompt="$1"
    local response_file="/tmp/llmtrace_response.json"
    
    curl -s "$LLMTRACE_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [
                {\"role\": \"system\", \"content\": \"You are a helpful assistant.\"},
                {\"role\": \"user\", \"content\": \"$prompt\"}
            ],
            \"temperature\": 0.7,
            \"max_tokens\": 150
        }" > "$response_file"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Request successful${NC}"
        echo -e "${YELLOW}📝 Response:${NC}"
        cat "$response_file" | jq -r '.choices[0].message.content'
        
        echo -e "\n${YELLOW}📊 Usage:${NC}"
        cat "$response_file" | jq '.usage'
        
        # Extract completion ID for trace lookup
        local completion_id=$(cat "$response_file" | jq -r '.id')
        echo -e "\n${YELLOW}🆔 Completion ID: $completion_id${NC}"
        
        rm -f "$response_file"
        return 0
    else
        echo -e "${RED}❌ Request failed${NC}"
        cat "$response_file" 2>/dev/null | jq 2>/dev/null || echo "No JSON response"
        rm -f "$response_file"
        return 1
    fi
}

# Function to send streaming request
send_streaming_request() {
    echo -e "\n${BLUE}🌊 Sending streaming request...${NC}"
    
    local prompt="$1"
    
    echo -e "${YELLOW}📝 Streaming response:${NC}"
    echo "---"
    
    curl -s -N "$LLMTRACE_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [
                {\"role\": \"user\", \"content\": \"$prompt\"}
            ],
            \"stream\": true,
            \"max_tokens\": 100
        }" | while IFS= read -r line; do
        if [[ $line == data:* ]]; then
            content=$(echo "$line" | sed 's/^data: //' | jq -r '.choices[0].delta.content // empty' 2>/dev/null)
            if [ -n "$content" ] && [ "$content" != "null" ]; then
                printf "$content"
            fi
        fi
    done
    
    echo -e "\n---"
    echo -e "${GREEN}✅ Streaming complete${NC}"
}

# Function to check traces
check_traces() {
    echo -e "\n${BLUE}🔍 Checking recent traces...${NC}"
    
    local traces=$(curl -s "$LLMTRACE_URL/traces?limit=5")
    local trace_count=$(echo "$traces" | jq length)
    
    echo -e "${GREEN}📈 Found $trace_count recent traces${NC}"
    
    if [ "$trace_count" -gt 0 ]; then
        echo "$traces" | jq -r '.[] | "• \(.trace_id[0:8])... - \(.model_name) (\(.duration_ms)ms, \(.total_tokens) tokens)"' | head -3
        
        # Get detailed info for latest trace
        local latest_trace_id=$(echo "$traces" | jq -r '.[0].trace_id')
        echo -e "\n${YELLOW}🔬 Latest trace details:${NC}"
        curl -s "$LLMTRACE_URL/traces/$latest_trace_id" | jq '{
            trace_id,
            model_name,
            duration_ms,
            total_tokens,
            security_score,
            cost_usd
        }'
    else
        echo -e "${YELLOW}⚠️ No traces found${NC}"
    fi
}

# Function to check security findings
check_security() {
    echo -e "\n${BLUE}🛡️ Checking security findings...${NC}"
    
    local findings=$(curl -s "$LLMTRACE_URL/security/findings")
    local finding_count=$(echo "$findings" | jq length)
    
    if [ "$finding_count" -gt 0 ]; then
        echo -e "${YELLOW}⚠️ Found $finding_count security findings${NC}"
        echo "$findings" | jq -r '.[] | "• \(.severity | ascii_upcase): \(.title)"' | head -3
    else
        echo -e "${GREEN}✅ No security issues detected${NC}"
    fi
}

# Function to get cost metrics
get_cost_metrics() {
    echo -e "\n${BLUE}💰 Getting cost metrics...${NC}"
    
    local metrics=$(curl -s "$LLMTRACE_URL/metrics/costs")
    
    echo -e "${YELLOW}💵 Cost Summary:${NC}"
    echo "$metrics" | jq '{
        total_cost_usd,
        total_requests: .requests_processed // "N/A",
        avg_cost_per_request
    }'
    
    if echo "$metrics" | jq -e '.breakdown' > /dev/null 2>&1; then
        echo -e "\n${YELLOW}📊 By Model:${NC}"
        echo "$metrics" | jq -r '.breakdown | to_entries[] | "• \(.key): $\(.value.cost_usd) (\(.value.requests) requests)"' | head -3
    fi
}

# Function to test function calling
test_function_calling() {
    echo -e "\n${BLUE}🔧 Testing function calling...${NC}"
    
    curl -s "$LLMTRACE_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d '{
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "What is the weather like in Paris?"}
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get current weather for a location",
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
            ],
            "tool_choice": "auto"
        }' > /tmp/function_response.json
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Function calling request successful${NC}"
        
        local has_function_call=$(cat /tmp/function_response.json | jq -e '.choices[0].message.tool_calls // false')
        if [ "$has_function_call" != "false" ]; then
            echo -e "${YELLOW}🔧 Function called:${NC}"
            cat /tmp/function_response.json | jq '.choices[0].message.tool_calls[0].function'
        else
            echo -e "${YELLOW}💬 Regular response:${NC}"
            cat /tmp/function_response.json | jq -r '.choices[0].message.content'
        fi
    else
        echo -e "${RED}❌ Function calling failed${NC}"
    fi
    
    rm -f /tmp/function_response.json
}

# Main execution
main() {
    check_llmtrace
    
    echo -e "\n${BLUE}🎯 Running demo scenarios...${NC}"
    
    # Scenario 1: Basic chat
    send_chat_request "Explain machine learning in one sentence"
    
    # Scenario 2: Streaming
    send_streaming_request "Write a haiku about programming"
    
    # Scenario 3: Function calling
    test_function_calling
    
    # Give LLMTrace time to process
    echo -e "\n${BLUE}⏱️ Waiting for trace processing...${NC}"
    sleep 2
    
    # Check results
    check_traces
    check_security
    get_cost_metrics
    
    echo -e "\n${GREEN}✅ Demo completed!${NC}"
    echo -e "${BLUE}🔗 Useful URLs:${NC}"
    echo "  • Traces: $LLMTRACE_URL/traces"
    echo "  • Security: $LLMTRACE_URL/security/findings" 
    echo "  • Metrics: $LLMTRACE_URL/metrics/costs"
    echo "  • Health: $LLMTRACE_URL/health"
}

# Run main function
main "$@"