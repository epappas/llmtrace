#!/bin/bash

# LLMTrace API exploration script
# Demonstrates all available REST API endpoints

set -e

LLMTRACE_URL="http://localhost:8080"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PURPLE}🔍 LLMTrace API Explorer${NC}"
echo "=========================="

# Test endpoint with proper error handling
test_endpoint() {
    local method="$1"
    local endpoint="$2" 
    local description="$3"
    local data="$4"
    
    echo -e "\n${CYAN}$method $endpoint${NC}"
    echo -e "${YELLOW}📖 $description${NC}"
    
    local curl_args=(-s -w "HTTP %{http_code}")
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        curl_args+=(-X POST -H "Content-Type: application/json" -d "$data")
    elif [ "$method" = "DELETE" ]; then
        curl_args+=(-X DELETE)
    fi
    
    local response=$(curl "${curl_args[@]}" "$LLMTRACE_URL$endpoint")
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" == *"200"* ]] || [[ "$http_code" == *"201"* ]]; then
        echo -e "${GREEN}✅ $http_code${NC}"
        if [ -n "$body" ] && echo "$body" | jq . >/dev/null 2>&1; then
            echo "$body" | jq . | head -10
            local line_count=$(echo "$body" | jq . | wc -l)
            if [ "$line_count" -gt 10 ]; then
                echo "... ($(($line_count - 10)) more lines)"
            fi
        else
            echo "${body:0:200}..."
        fi
    elif [[ "$http_code" == *"404"* ]]; then
        echo -e "${YELLOW}⚠️ $http_code (Not Found - may not be implemented)${NC}"
    else
        echo -e "${RED}❌ $http_code${NC}"
        echo "$body" | head -3
    fi
}

# Check health and basic info
explore_health_endpoints() {
    echo -e "\n${BLUE}🏥 Health & Status Endpoints${NC}"
    echo "=============================="
    
    test_endpoint "GET" "/health" "System health check"
    test_endpoint "GET" "/api/status" "Detailed system status"
    test_endpoint "GET" "/api/config" "Current configuration"
}

# Explore trace endpoints
explore_trace_endpoints() {
    echo -e "\n${BLUE}📊 Trace Endpoints${NC}"
    echo "==================="
    
    test_endpoint "GET" "/api/traces" "List recent traces"
    test_endpoint "GET" "/api/traces?limit=3" "List traces with limit"
    test_endpoint "GET" "/api/traces?model=gpt-4" "Filter traces by model"
    test_endpoint "GET" "/api/traces?has_security_findings=true" "Traces with security issues"
    
    # Get a trace ID for detailed lookup
    local traces=$(curl -s "$LLMTRACE_URL/api/traces?limit=1")
    local trace_id=$(echo "$traces" | jq -r '.[0].trace_id // empty' 2>/dev/null)
    
    if [ -n "$trace_id" ] && [ "$trace_id" != "null" ]; then
        test_endpoint "GET" "/api/traces/$trace_id" "Get specific trace details"
        test_endpoint "GET" "/api/traces/$trace_id/raw" "Get raw request/response"
    else
        echo -e "${YELLOW}⚠️ No traces available for detailed lookup${NC}"
    fi
}

# Explore security endpoints
explore_security_endpoints() {
    echo -e "\n${BLUE}🛡️ Security Endpoints${NC}"
    echo "======================"
    
    test_endpoint "GET" "/api/security/findings" "List security findings"
    test_endpoint "GET" "/api/security/findings?severity=high" "High severity findings"
    test_endpoint "GET" "/api/security/findings?finding_type=prompt_injection" "Prompt injection findings"
    test_endpoint "GET" "/api/security/stats" "Security statistics"
    
    # Get a finding ID for detailed lookup
    local findings=$(curl -s "$LLMTRACE_URL/api/security/findings?limit=1")
    local finding_id=$(echo "$findings" | jq -r '.[0].finding_id // empty' 2>/dev/null)
    
    if [ -n "$finding_id" ] && [ "$finding_id" != "null" ]; then
        test_endpoint "GET" "/api/security/findings/$finding_id" "Get finding details"
        # Test resolving a finding (this might be read-only)
        # test_endpoint "POST" "/api/security/findings/$finding_id/resolve" "Resolve finding" '{"resolution":"false_positive","notes":"Testing API"}'
    fi
}

# Explore metrics endpoints
explore_metrics_endpoints() {
    echo -e "\n${BLUE}📈 Metrics Endpoints${NC}"
    echo "===================="
    
    test_endpoint "GET" "/api/metrics/summary" "Overall metrics summary"
    test_endpoint "GET" "/api/metrics/costs" "Cost metrics"
    test_endpoint "GET" "/api/metrics/costs?period=day" "Daily cost metrics"
    test_endpoint "GET" "/api/metrics/costs?group_by=model" "Costs by model"
    test_endpoint "GET" "/api/metrics/costs?group_by=user" "Costs by user"
    test_endpoint "GET" "/api/metrics/performance" "Performance metrics"
    test_endpoint "GET" "/api/metrics/tokens" "Token usage metrics"
    test_endpoint "GET" "/api/metrics/latency" "Latency statistics"
    test_endpoint "GET" "/api/metrics/errors" "Error metrics"
}

# Explore analytics endpoints
explore_analytics_endpoints() {
    echo -e "\n${BLUE}📊 Analytics Endpoints${NC}"
    echo "======================"
    
    test_endpoint "GET" "/api/analytics/trends?metric=cost&period=week" "Cost trends"
    test_endpoint "GET" "/api/search?q=gpt-4&type=traces" "Search traces"
    test_endpoint "GET" "/api/search?q=injection&type=findings" "Search findings"
}

# Test configuration endpoints
explore_config_endpoints() {
    echo -e "\n${BLUE}⚙️ Configuration Endpoints${NC}"
    echo "=========================="
    
    test_endpoint "GET" "/api/config" "Get current config"
    
    # Test config validation (safe operation)
    test_endpoint "POST" "/api/config/validate" "Validate config" '{
        "security": {
            "enable_prompt_injection_detection": true,
            "prompt_injection_sensitivity": "high"
        }
    }'
}

# Test export endpoints
explore_export_endpoints() {
    echo -e "\n${BLUE}📤 Export Endpoints${NC}"
    echo "==================="
    
    test_endpoint "POST" "/api/traces/export" "Export traces" '{
        "format": "csv",
        "filters": {
            "limit": 10
        },
        "fields": ["trace_id", "model_name", "duration_ms", "total_tokens"]
    }'
}

# Test monitoring endpoints
explore_monitoring_endpoints() {
    echo -e "\n${BLUE}📡 Monitoring Endpoints${NC}"
    echo "======================="
    
    # Prometheus metrics (if enabled)
    test_endpoint "GET" "/metrics" "Prometheus metrics"
    
    # Circuit breaker status
    test_endpoint "GET" "/api/circuit-breaker/status" "Circuit breaker status"
}

# Test rate limiting behavior
test_rate_limiting() {
    echo -e "\n${BLUE}🚦 Testing Rate Limiting${NC}"
    echo "========================="
    
    echo -e "${YELLOW}Sending rapid requests to test rate limiting...${NC}"
    
    local rate_limited=0
    local successful=0
    
    for i in {1..10}; do
        local response=$(curl -s -w "HTTP %{http_code}" "$LLMTRACE_URL/api/traces?limit=1")
        local http_code=$(echo "$response" | tail -n1)
        
        if [[ "$http_code" == *"429"* ]]; then
            rate_limited=$((rate_limited + 1))
            echo -e "${RED}Request $i: Rate limited${NC}"
        elif [[ "$http_code" == *"200"* ]]; then
            successful=$((successful + 1))
            echo -e "${GREEN}Request $i: Success${NC}"
        else
            echo -e "${YELLOW}Request $i: $http_code${NC}"
        fi
        
        sleep 0.1
    done
    
    echo -e "\n${BLUE}Rate Limiting Results:${NC}"
    echo "• Successful: $successful"
    echo "• Rate Limited: $rate_limited"
    
    if [ "$rate_limited" -gt 0 ]; then
        echo -e "${GREEN}✅ Rate limiting is active${NC}"
    else
        echo -e "${YELLOW}ℹ️ No rate limiting detected (may not be configured)${NC}"
    fi
}

# Test error handling
test_error_scenarios() {
    echo -e "\n${BLUE}❌ Testing Error Scenarios${NC}"
    echo "=========================="
    
    test_endpoint "GET" "/api/traces/invalid-trace-id" "Invalid trace ID"
    test_endpoint "GET" "/api/security/findings/invalid-finding-id" "Invalid finding ID"
    test_endpoint "GET" "/api/nonexistent-endpoint" "Non-existent endpoint"
    test_endpoint "POST" "/api/traces" "POST to read-only endpoint" '{"invalid": "data"}'
    test_endpoint "DELETE" "/api/config" "DELETE on protected resource"
}

# Generate API documentation
generate_api_docs() {
    echo -e "\n${BLUE}📚 API Documentation Summary${NC}"
    echo "============================="
    
    echo -e "${GREEN}Available Endpoints:${NC}"
    echo ""
    echo "HEALTH & STATUS:"
    echo "  GET  /health                    - System health check"
    echo "  GET  /api/status               - Detailed system status"
    echo "  GET  /api/config               - Current configuration"
    echo ""
    echo "TRACES:"
    echo "  GET  /api/traces               - List traces"
    echo "  GET  /api/traces/{id}          - Get trace details"
    echo "  GET  /api/traces/{id}/raw      - Get raw request/response"
    echo "  POST /api/traces/export        - Export traces"
    echo ""
    echo "SECURITY:"
    echo "  GET  /api/security/findings    - List security findings"
    echo "  GET  /api/security/findings/{id} - Get finding details"
    echo "  POST /api/security/findings/{id}/resolve - Resolve finding"
    echo "  GET  /api/security/stats       - Security statistics"
    echo ""
    echo "METRICS:"
    echo "  GET  /api/metrics/summary      - Overall metrics"
    echo "  GET  /api/metrics/costs        - Cost metrics"
    echo "  GET  /api/metrics/performance  - Performance metrics"
    echo "  GET  /api/metrics/tokens       - Token usage"
    echo ""
    echo "ANALYTICS:"
    echo "  GET  /api/analytics/trends     - Trend analysis"
    echo "  GET  /api/search              - Search across data"
    echo ""
    echo "CONFIGURATION:"
    echo "  POST /api/config/validate      - Validate configuration"
    echo ""
    echo -e "${YELLOW}Query Parameters:${NC}"
    echo "  limit, offset     - Pagination"
    echo "  start_time, end_time - Time range filters"
    echo "  model, tenant_id  - Entity filters"
    echo "  severity, type    - Security filters"
    echo "  group_by, period  - Aggregation options"
    echo ""
    echo -e "${BLUE}For full API documentation, see: docs/api/rest-api.md${NC}"
}

# Interactive API explorer
interactive_explorer() {
    echo -e "\n${BLUE}🔍 Interactive API Explorer${NC}"
    echo "=========================="
    
    while true; do
        echo -e "\nChoose an option:"
        echo "1) Custom GET request"
        echo "2) Custom POST request"
        echo "3) List available endpoints"
        echo "4) Exit"
        
        read -p "Enter choice (1-4): " choice
        
        case $choice in
            1)
                read -p "Enter endpoint (e.g., /api/traces): " endpoint
                test_endpoint "GET" "$endpoint" "Custom GET request"
                ;;
            2)
                read -p "Enter endpoint: " endpoint
                read -p "Enter JSON data (or press Enter for empty): " data
                test_endpoint "POST" "$endpoint" "Custom POST request" "$data"
                ;;
            3)
                generate_api_docs
                ;;
            4)
                echo "Goodbye!"
                break
                ;;
            *)
                echo "Invalid choice"
                ;;
        esac
    done
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
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}⚠️ jq not found. Install jq for better output formatting.${NC}"
    fi
    
    # Explore all API endpoints
    explore_health_endpoints
    explore_trace_endpoints
    explore_security_endpoints
    explore_metrics_endpoints
    explore_analytics_endpoints
    explore_config_endpoints
    explore_export_endpoints
    explore_monitoring_endpoints
    
    # Test behaviors
    test_rate_limiting
    test_error_scenarios
    
    # Generate documentation
    generate_api_docs
    
    # Ask if user wants interactive mode
    echo -e "\n${BLUE}API exploration complete!${NC}"
    read -p "Enter interactive mode? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        interactive_explorer
    fi
}

# Check for help flag
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "LLMTrace API Explorer"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo ""
    echo "Environment:"
    echo "  LLMTRACE_URL  LLMTrace base URL (default: http://localhost:8080)"
    echo ""
    echo "This script explores all available LLMTrace REST API endpoints."
    echo "It tests each endpoint and shows example responses."
    exit 0
fi

main "$@"