#!/bin/bash

# API Key for testing
API_KEY="d1d604186fcb886e85f1b20eb64524c554365bbd042349c4e94cfa71cccde462"
BASE_URL="http://localhost:8080"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🚀 Testing Agent and LLM Endpoints..."
echo "======================================="

# Test 1: Register a new agent
echo -e "\n${GREEN}1. Testing Agent Registration${NC}"
curl -X POST "$BASE_URL/api/agents/register" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-002",
    "registration_time": "2025-08-01T23:00:00Z",
    "client_id": "test_client_1754071141650",
    "metadata": {
      "version": "1.0.0",
      "environment": "production"
    }
  }'

# Test 2: Update agent status
echo -e "\n\n${GREEN}2. Testing Agent Status Update${NC}"
curl -X POST "$BASE_URL/api/agents/status" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "status": "active",
    "timestamp": "2025-08-01T23:01:00Z",
    "client_id": "test_client_1754071141650",
    "previous_status": null,
    "metadata": {
      "cpu_usage": 45,
      "memory_usage": 128
    }
  }'

# Test 3: Log agent activity
echo -e "\n\n${GREEN}3. Testing Agent Activity Logging${NC}"
curl -X POST "$BASE_URL/api/agents/activity" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "action": "process_request",
    "timestamp": "2025-08-01T23:02:00Z",
    "client_id": "test_client_1754071141650",
    "details": {
      "request_id": "req-001",
      "duration_ms": 150
    },
    "duration": 150
  }'

# Test 4: Get active agents
echo -e "\n\n${GREEN}4. Testing Get Active Agents${NC}"
curl -X GET "$BASE_URL/api/agents/active" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json"

# Test 5: Get agent status
echo -e "\n\n${GREEN}5. Testing Get Agent Status${NC}"
curl -X GET "$BASE_URL/api/agents/test-agent-001/status" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json"

# Test 6: Get agent activity
echo -e "\n\n${GREEN}6. Testing Get Agent Activity${NC}"
curl -X GET "$BASE_URL/api/agents/test-agent-001/activity?limit=5" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json"

# Test 7: Log LLM usage
echo -e "\n\n${GREEN}7. Testing LLM Usage Logging${NC}"
curl -X POST "$BASE_URL/api/sdk/llm-usage" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-08-01T23:03:00Z",
    "agent_id": "test-agent-001",
    "provider": "anthropic",
    "model": "claude-3-opus-20240229",
    "tokens_input": 2500,
    "tokens_output": 1200,
    "client_id": "test_client_1754071141650",
    "metadata": {
      "request_id": "req-004",
      "user_id": "user-123",
      "conversation_turn": 1
    }
  }'

# Test 8: Get LLM usage aggregated
echo -e "\n\n${GREEN}8. Testing Get LLM Usage Aggregated${NC}"
curl -X GET "$BASE_URL/api/llm-usage/aggregated?timeframe=24h" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json"

# Test 9: Get operations overview
echo -e "\n\n${GREEN}9. Testing Get Operations Overview${NC}"
curl -X GET "$BASE_URL/api/agents/operations/overview" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json"

echo -e "\n\n${GREEN}Testing Complete! 🎉${NC}" 