#!/bin/bash

# Cost monitoring and budget management with LLMTrace
# Demonstrates cost tracking, budget alerts, and usage analytics

set -e

LLMTRACE_URL="http://localhost:8080"
OPENAI_API_KEY="${OPENAI_API_KEY}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}💰 LLMTrace Cost Monitoring${NC}"
echo "============================="

# Check prerequisites
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}❌ Please set OPENAI_API_KEY environment variable${NC}"
    exit 1
fi

# Generate some usage for cost tracking
generate_sample_usage() {
    echo -e "\n${BLUE}🏭 Generating sample usage for cost analysis...${NC}"
    
    local models=("gpt-4" "gpt-3.5-turbo")
    local prompts=(
        "Explain quantum computing"
        "Write a Python function to sort a list"
        "What are the benefits of cloud computing?"
        "Describe machine learning algorithms"
        "How does blockchain technology work?"
    )
    
    for i in {1..10}; do
        local model=${models[$((RANDOM % ${#models[@]}))]}
        local prompt=${prompts[$((RANDOM % ${#prompts[@]}))]}
        local max_tokens=$((50 + RANDOM % 150))
        
        echo -e "${YELLOW}Request $i: $model - ${prompt:0:30}...${NC}"
        
        curl -s "$LLMTRACE_URL/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -H "X-LLMTrace-User-ID: user_$((RANDOM % 3 + 1))" \
            -H "X-LLMTrace-Feature: cost_demo" \
            -d "{
                \"model\": \"$model\",
                \"messages\": [
                    {\"role\": \"user\", \"content\": \"$prompt\"}
                ],
                \"max_tokens\": $max_tokens,
                \"temperature\": 0.7
            }" > /dev/null
        
        sleep 0.5  # Prevent rate limiting
    done
    
    echo -e "${GREEN}✅ Generated sample usage${NC}"
}

# Get overall cost metrics
get_cost_overview() {
    echo -e "\n${BLUE}📊 Cost Overview${NC}"
    
    local metrics=$(curl -s "$LLMTRACE_URL/metrics/costs")
    
    if echo "$metrics" | jq -e '.total_cost_usd' > /dev/null 2>&1; then
        echo -e "${GREEN}💵 Total Cost: $$(echo "$metrics" | jq -r '.total_cost_usd')${NC}"
        echo -e "${YELLOW}📈 Total Requests: $(echo "$metrics" | jq -r '.total_requests // "N/A"')${NC}"
        echo -e "${YELLOW}📊 Average Cost per Request: $$(echo "$metrics" | jq -r '.avg_cost_per_request // "N/A"')${NC}"
        
        # Budget status if available
        if echo "$metrics" | jq -e '.budget_status' > /dev/null 2>&1; then
            echo -e "\n${BLUE}📋 Budget Status:${NC}"
            echo "$metrics" | jq -r '.budget_status | "Daily Budget: $\(.daily_budget_usd // "N/A")\nSpent Today: $\(.spent_today_usd // "N/A")\nRemaining: $\(.remaining_today_usd // "N/A")\nUtilization: \((.budget_utilization // 0) * 100 | floor)%"'
        fi
    else
        echo -e "${YELLOW}⚠️ No cost data available yet${NC}"
    fi
}

# Get cost breakdown by model
get_model_costs() {
    echo -e "\n${BLUE}🤖 Cost Breakdown by Model${NC}"
    
    local metrics=$(curl -s "$LLMTRACE_URL/metrics/costs?group_by=model")
    
    if echo "$metrics" | jq -e '.breakdown' > /dev/null 2>&1; then
        echo "$metrics" | jq -r '.breakdown | to_entries[] | "• \(.key): $\(.value.cost_usd) (\(.value.requests) requests, \(.value.tokens) tokens)"'
    else
        echo -e "${YELLOW}⚠️ Model breakdown not available${NC}"
    fi
}

# Get cost trends over time
get_cost_trends() {
    echo -e "\n${BLUE}📈 Cost Trends${NC}"
    
    # Daily costs
    local daily_costs=$(curl -s "$LLMTRACE_URL/metrics/costs?period=daily")
    
    if echo "$daily_costs" | jq -e '.trends.daily_costs' > /dev/null 2>&1; then
        echo -e "${YELLOW}📅 Daily Costs (last 7 days):${NC}"
        echo "$daily_costs" | jq -r '.trends.daily_costs[] | "\(.date): $\(.cost_usd)"' | tail -7
    fi
    
    # Hourly costs for today
    local hourly_costs=$(curl -s "$LLMTRACE_URL/metrics/costs?period=hour")
    
    if echo "$hourly_costs" | jq -e '.hourly_breakdown' > /dev/null 2>&1; then
        echo -e "\n${YELLOW}⏰ Hourly Costs (today):${NC}"
        echo "$hourly_costs" | jq -r '.hourly_breakdown | to_entries | sort_by(.key) | reverse | .[:5][] | "\(.key):00 - $\(.value.cost_usd) (\(.value.requests) requests)"'
    fi
}

# Check for cost anomalies
check_cost_anomalies() {
    echo -e "\n${BLUE}🚨 Cost Anomaly Detection${NC}"
    
    # Check if anomaly detection is configured
    local config=$(curl -s "$LLMTRACE_URL/config")
    
    if echo "$config" | jq -e '.anomaly_detection.enabled' > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Anomaly detection is enabled${NC}"
        
        # Get recent anomalies
        local anomalies=$(curl -s "$LLMTRACE_URL/metrics/anomalies?type=cost")
        
        if echo "$anomalies" | jq -e '.[]' > /dev/null 2>&1; then
            echo -e "${RED}⚠️ Cost Anomalies Detected:${NC}"
            echo "$anomalies" | jq -r '.[] | "• \(.timestamp): \(.description) (severity: \(.severity))"'
        else
            echo -e "${GREEN}✅ No cost anomalies detected${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Anomaly detection not configured${NC}"
    fi
}

# Get user/tenant cost breakdown
get_user_costs() {
    echo -e "\n${BLUE}👥 Cost by User/Tenant${NC}"
    
    local user_metrics=$(curl -s "$LLMTRACE_URL/metrics/costs?group_by=user")
    
    if echo "$user_metrics" | jq -e '.breakdown' > /dev/null 2>&1; then
        echo -e "${YELLOW}👤 Top Users by Cost:${NC}"
        echo "$user_metrics" | jq -r '.breakdown | to_entries | sort_by(.value.cost_usd) | reverse | .[:5][] | "• \(.key): $\(.value.cost_usd) (\(.value.requests) requests)"'
    fi
    
    local tenant_metrics=$(curl -s "$LLMTRACE_URL/metrics/costs?group_by=tenant")
    
    if echo "$tenant_metrics" | jq -e '.breakdown' > /dev/null 2>&1; then
        echo -e "\n${YELLOW}🏢 Cost by Tenant:${NC}"
        echo "$tenant_metrics" | jq -r '.breakdown | to_entries | sort_by(.value.cost_usd) | reverse | .[:5][] | "• \(.key): $\(.value.cost_usd) (\(.value.requests) requests)"'
    fi
}

# Token usage analysis
analyze_token_usage() {
    echo -e "\n${BLUE}🎯 Token Usage Analysis${NC}"
    
    local token_metrics=$(curl -s "$LLMTRACE_URL/metrics/tokens")
    
    if echo "$token_metrics" | jq -e '.total_tokens' > /dev/null 2>&1; then
        echo -e "${GREEN}📊 Total Tokens: $(echo "$token_metrics" | jq -r '.total_tokens | tonumber | . as $n | if $n > 1000000 then ($n/1000000 | floor | tostring) + "M" elif $n > 1000 then ($n/1000 | floor | tostring) + "K" else tostring end')${NC}"
        echo -e "${YELLOW}📝 Prompt Tokens: $(echo "$token_metrics" | jq -r '.prompt_tokens')${NC}"
        echo -e "${YELLOW}💬 Completion Tokens: $(echo "$token_metrics" | jq -r '.completion_tokens')${NC}"
        echo -e "${YELLOW}📈 Avg Tokens/Request: $(echo "$token_metrics" | jq -r '.avg_tokens_per_request')${NC}"
        
        # Token usage by model
        if echo "$token_metrics" | jq -e '.by_model' > /dev/null 2>&1; then
            echo -e "\n${YELLOW}🤖 Token Usage by Model:${NC}"
            echo "$token_metrics" | jq -r '.by_model | to_entries[] | "• \(.key): \(.value.total_tokens) tokens (avg: \(.value.avg_prompt_tokens) + \(.value.avg_completion_tokens))"'
        fi
    else
        echo -e "${YELLOW}⚠️ Token metrics not available${NC}"
    fi
}

# Test cost controls
test_cost_controls() {
    echo -e "\n${BLUE}🔒 Testing Cost Controls${NC}"
    
    # Check current cost control configuration
    local config=$(curl -s "$LLMTRACE_URL/config")
    
    if echo "$config" | jq -e '.cost_control.enabled' > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Cost controls are enabled${NC}"
        
        echo -e "${YELLOW}💰 Daily Budget: $$(echo "$config" | jq -r '.cost_control.daily_budget_usd // "Not set"')${NC}"
        echo -e "${YELLOW}👤 Per-Agent Budget: $$(echo "$config" | jq -r '.cost_control.per_agent_daily_budget_usd // "Not set"')${NC}"
        
        # Test with a request that might hit limits
        echo -e "\n${BLUE}🧪 Testing budget enforcement...${NC}"
        
        local large_request_response=$(curl -s "$LLMTRACE_URL/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d '{
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "Write a very detailed explanation of machine learning"}
                ],
                "max_tokens": 2000
            }')
        
        if echo "$large_request_response" | jq -e '.error' > /dev/null; then
            echo -e "${RED}🚫 Request blocked by cost controls:${NC}"
            echo "$large_request_response" | jq -r '.error.message'
        else
            echo -e "${GREEN}✅ Request processed (within budget)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Cost controls are not enabled${NC}"
        echo "Enable in config.yaml: cost_control.enabled = true"
    fi
}

# Generate cost report
generate_cost_report() {
    echo -e "\n${BLUE}📄 Generating Cost Report${NC}"
    
    local report_file="/tmp/llmtrace_cost_report.json"
    
    # Collect all cost data
    local overview=$(curl -s "$LLMTRACE_URL/metrics/costs")
    local by_model=$(curl -s "$LLMTRACE_URL/metrics/costs?group_by=model")
    local by_user=$(curl -s "$LLMTRACE_URL/metrics/costs?group_by=user")
    local tokens=$(curl -s "$LLMTRACE_URL/metrics/tokens")
    
    # Create comprehensive report
    jq -n \
        --argjson overview "$overview" \
        --argjson by_model "$by_model" \
        --argjson by_user "$by_user" \
        --argjson tokens "$tokens" \
        '{
            "report_generated": now | strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_cost_usd": $overview.total_cost_usd,
                "total_requests": $overview.total_requests,
                "total_tokens": $tokens.total_tokens,
                "avg_cost_per_request": $overview.avg_cost_per_request
            },
            "breakdown": {
                "by_model": $by_model.breakdown,
                "by_user": $by_user.breakdown
            },
            "token_analysis": {
                "prompt_tokens": $tokens.prompt_tokens,
                "completion_tokens": $tokens.completion_tokens,
                "efficiency": ($tokens.completion_tokens / $tokens.prompt_tokens)
            }
        }' > "$report_file"
    
    echo -e "${GREEN}✅ Cost report generated: $report_file${NC}"
    echo -e "${BLUE}📊 Report Summary:${NC}"
    cat "$report_file" | jq '.summary'
}

# Monitor real-time costs
monitor_realtime_costs() {
    echo -e "\n${BLUE}⚡ Real-time Cost Monitoring (10 requests)${NC}"
    echo "Press Ctrl+C to stop"
    
    local initial_cost=$(curl -s "$LLMTRACE_URL/metrics/costs" | jq -r '.total_cost_usd // 0')
    local initial_requests=$(curl -s "$LLMTRACE_URL/metrics/costs" | jq -r '.total_requests // 0')
    
    echo -e "${YELLOW}Starting cost: $$initial_cost${NC}"
    echo -e "${YELLOW}Starting requests: $initial_requests${NC}"
    echo ""
    
    for i in {1..10}; do
        # Make a request
        curl -s "$LLMTRACE_URL/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d "{
                \"model\": \"gpt-3.5-turbo\",
                \"messages\": [
                    {\"role\": \"user\", \"content\": \"Request $i: What is $(shuf -n 1 -e 'Python' 'JavaScript' 'Java' 'Go' 'Rust')?\"}
                ],
                \"max_tokens\": 50
            }" > /dev/null
        
        sleep 2  # Wait for processing
        
        # Check current cost
        local current_metrics=$(curl -s "$LLMTRACE_URL/metrics/costs")
        local current_cost=$(echo "$current_metrics" | jq -r '.total_cost_usd // 0')
        local current_requests=$(echo "$current_metrics" | jq -r '.total_requests // 0')
        
        local cost_diff=$(echo "$current_cost - $initial_cost" | bc -l 2>/dev/null || echo "0")
        local requests_diff=$((current_requests - initial_requests))
        
        echo -e "${GREEN}Request $i: +$${cost_diff} (Total: $$current_cost, Requests: +$requests_diff)${NC}"
        
        sleep 1
    done
    
    echo -e "\n${BLUE}✅ Real-time monitoring complete${NC}"
}

# Main execution
main() {
    # Check if LLMTrace is running
    if ! curl -s -f "$LLMTRACE_URL/health" > /dev/null; then
        echo -e "${RED}❌ LLMTrace is not reachable at $LLMTRACE_URL${NC}"
        echo "Please start LLMTrace: docker compose up -d"
        exit 1
    fi
    
    echo -e "${GREEN}✅ LLMTrace is running${NC}"
    
    # Generate some usage if needed
    local trace_count=$(curl -s "$LLMTRACE_URL/traces" | jq length)
    if [ "$trace_count" -lt 5 ]; then
        generate_sample_usage
        echo -e "${BLUE}⏱️ Waiting for cost calculation...${NC}"
        sleep 3
    fi
    
    # Run cost analysis
    get_cost_overview
    get_model_costs
    get_cost_trends
    check_cost_anomalies
    get_user_costs
    analyze_token_usage
    test_cost_controls
    
    # Generate report
    generate_cost_report
    
    # Optional: real-time monitoring
    read -p "Run real-time cost monitoring? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        monitor_realtime_costs
    fi
    
    echo -e "\n${GREEN}✅ Cost monitoring completed!${NC}"
    echo -e "${BLUE}🔗 Cost dashboard: $LLMTRACE_URL/metrics/costs${NC}"
    echo -e "${BLUE}📊 Token metrics: $LLMTRACE_URL/metrics/tokens${NC}"
}

main "$@"