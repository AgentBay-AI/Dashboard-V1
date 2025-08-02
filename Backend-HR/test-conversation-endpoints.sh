#!/bin/bash

# AI Agent Conversation & Metrics API Test Script
# Test all conversation and metrics endpoints

API_BASE_URL="http://localhost:8080/api"
API_KEY="3301f4d913aa2e2a928a3686bdc17e33"
CLIENT_ID="test_client_1754071141650"

echo "🚀 Testing AI Agent Conversation & Metrics API Endpoints"
echo "========================================================"

# Function to make API call
make_request() {
  local method=$1
  local endpoint=$2
  local data=$3
  
  echo ""
  echo "📡 $method $endpoint"
  echo "-------------------"
  
  if [ "$method" = "GET" ]; then
    curl -s \
      -H "Authorization: Bearer $API_KEY" \
      -H "Content-Type: application/json" \
      "$API_BASE_URL$endpoint" | jq '.' || true
  else
    curl -s \
      -X $method \
      -H "Authorization: Bearer $API_KEY" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "$API_BASE_URL$endpoint" | jq '.' || true
  fi
}

# Test 1: Start a conversation
echo "🟢 Starting conversation..."
make_request "POST" "/conversations/start" '{
  "session_id": "test_session_001",
  "agent_id": "agent_001",
  "client_id": "'$CLIENT_ID'",
  "metadata": {
    "user_type": "premium",
    "channel": "web"
  }
}'

# Test 2: Add messages to conversation
echo "🟢 Adding user message..."
make_request "POST" "/conversations/message" '{
  "session_id": "test_session_001",
  "agent_id": "agent_001",
  "message_type": "user",
  "content": "Hello, I need help with my account",
  "token_count": 10
}'

echo "🟢 Adding assistant message..."
make_request "POST" "/conversations/message" '{
  "session_id": "test_session_001",
  "agent_id": "agent_001",
  "message_type": "assistant",
  "content": "I can help you with your account. What specific issue are you experiencing?",
  "response_time_ms": 850,
  "token_count": 20,
  "metadata": {
    "confidence": 0.95,
    "model": "gpt-4"
  }
}'

# Test 3: Get conversation history
echo "🟢 Getting conversation history..."
make_request "GET" "/conversations/test_session_001/history"

# Test 4: End conversation with quality score
echo "🟢 Ending conversation..."
make_request "POST" "/conversations/end" '{
  "session_id": "test_session_001",
  "quality_score": 4.5,
  "metadata": {
    "resolution": "complete",
    "user_satisfaction": "high"
  }
}'

# Test 5: Start another conversation for testing
echo "🟢 Starting second conversation..."
make_request "POST" "/conversations/start" '{
  "session_id": "test_session_002",
  "agent_id": "agent_002",
  "client_id": "'$CLIENT_ID'",
  "metadata": {
    "user_type": "standard",
    "channel": "mobile"
  }
}'

# Test 6: Mark session as failed
echo "🟢 Marking session as failed..."
make_request "POST" "/conversations/failed-session" '{
  "session_id": "test_session_002",
  "agent_id": "agent_002",
  "client_id": "'$CLIENT_ID'",
  "failure_reason": "user_timeout",
  "error_details": {
    "timeout_duration": 300,
    "last_activity": "user_message"
  }
}'

# Test 7: Get active conversations
echo "🟢 Getting active conversations..."
make_request "GET" "/conversations/active"

# Test 8: Test metrics endpoints
echo ""
echo "📊 Testing Metrics Endpoints"
echo "============================"

echo "🟢 Getting metrics overview..."
make_request "GET" "/metrics/overview"

echo "🟢 Getting success rates..."
make_request "GET" "/metrics/success-rates"

echo "🟢 Getting response times..."
make_request "GET" "/metrics/response-times"

echo "🟢 Getting quality metrics..."
make_request "GET" "/metrics/quality"

# Test 9: Test existing endpoints to ensure they still work
echo ""
echo "🔄 Testing Existing Endpoints"
echo "============================="

echo "🟢 Getting agent operations overview..."
make_request "GET" "/agents/operations/overview"

echo "🟢 Getting LLM usage aggregated..."
make_request "GET" "/llm-usage/aggregated?timeframe=24h"

echo ""
echo "✅ All tests completed!"
echo "======================" 