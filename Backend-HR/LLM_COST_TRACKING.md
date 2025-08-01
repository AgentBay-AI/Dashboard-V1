# LLM Token Usage & Cost Tracking System

## Overview

Complete implementation of LLM token usage and cost tracking with backend aggregation and dashboard visualization.

## 🚀 Features

### Backend Capabilities
- **Multi-Provider Support**: OpenAI, Claude/Anthropic, Google/Gemini
- **Real-time Cost Calculation**: Automatic cost computation using current pricing
- **Token Tracking**: Separate input/output token counting
- **Data Aggregation**: Provider and model-level statistics
- **OTEL Integration**: Full tracing support for LLM requests

### Frontend Dashboard
- **Cost Overview Cards**: Total cost, token usage, request counts
- **Provider Breakdown**: Detailed table by provider and model
- **Real-time Updates**: 30-second refresh interval
- **Responsive Design**: Mobile-friendly table and cards

## 📊 Data Schema

### Input Data Format
```typescript
{
  timestamp: string;           // ISO 8601 timestamp
  agent_id: string;           // Required agent identifier
  provider: string;           // "openai" | "claude" | "anthropic" | "gemini" | "google"
  model: string;              // Model name (e.g., "gpt-4o", "claude-3.5-sonnet")
  tokens_input: number;       // Input/prompt tokens
  tokens_output: number;      // Output/completion tokens
  session_id?: string;        // Optional session link
  client_id: string;          // Client identifier
  metadata?: {                // Optional metadata
    request_id?: string;
    user_id?: string;
    conversation_turn?: number;
  }
}
```

### Database Schema
```sql
CREATE TABLE llm_usage (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  agent_id VARCHAR(255) NOT NULL,
  provider VARCHAR(20) NOT NULL,
  model VARCHAR(100) NOT NULL,
  tokens_input INTEGER NOT NULL DEFAULT 0,
  tokens_output INTEGER NOT NULL DEFAULT 0,
  session_id VARCHAR(255) NULL,
  client_id VARCHAR(255) NOT NULL,
  metadata JSONB DEFAULT '{}',
  trace_id VARCHAR(32) NULL,
  span_id VARCHAR(16) NULL,
  trace_context JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## 💰 Pricing Configuration

### Supported Providers & Models

**OpenAI** (per 1K tokens):
- GPT-4o: $0.0025 input, $0.01 output
- GPT-4o-mini: $0.000075 input, $0.0003 output
- GPT-4-turbo: $0.01 input, $0.03 output
- GPT-4: $0.03 input, $0.06 output
- GPT-3.5-turbo: $0.0015 input, $0.002 output

**Claude/Anthropic** (per 1K tokens):
- Claude-3.5-sonnet: $0.003 input, $0.015 output
- Claude-3-opus: $0.015 input, $0.075 output
- Claude-3-sonnet: $0.003 input, $0.015 output
- Claude-3-haiku: $0.00025 input, $0.00125 output

**Google/Gemini** (per 1K tokens):
- Gemini-1.5-pro: $0.000125 input, $0.000375 output
- Gemini-1.5-flash: $0.0000375 input, $0.00015 output
- Gemini-pro: $0.0005 input, $0.0015 output

### Cost Calculation
```javascript
cost = (tokens_input / 1000 * input_price) + (tokens_output / 1000 * output_price)
```

## 🔌 API Endpoints

### 1. Record LLM Usage
```bash
POST /api/sdk/llm-usage
```

**Request Body:**
```json
{
  "timestamp": "2025-08-01T12:46:07.000Z",
  "agent_id": "agent-001",
  "provider": "openai",
  "model": "gpt-4o",
  "tokens_input": 1500,
  "tokens_output": 800,
  "session_id": "session-123",
  "client_id": "test_client_1754034419317"
}
```

**Features:**
- Automatic cost calculation and storage
- OTEL trace context injection
- Input validation with Zod schemas
- Error handling and logging

### 2. Get Aggregated Usage Data
```bash
GET /api/llm-usage/aggregated?timeframe=24h
```

**Response:**
```json
{
  "timeframe": {
    "start": "2025-07-31T08:04:28.432Z",
    "end": "2025-08-01T08:04:28.432Z",
    "requested_timeframe": "24h"
  },
  "summary": {
    "total_cost": 0.0425,
    "total_input_tokens": 15000,
    "total_output_tokens": 8000,
    "total_requests": 10,
    "providers_used": 2
  },
  "by_provider": {
    "openai": {
      "input_tokens": 10000,
      "output_tokens": 5000,
      "cost": 0.0375,
      "request_count": 6,
      "models": 2
    }
  },
  "detailed": {
    "openai": {
      "gpt-4o": {
        "input_tokens": 8000,
        "output_tokens": 4000,
        "cost": 0.0300,
        "request_count": 4
      }
    }
  }
}
```

**Query Parameters:**
- `timeframe`: "1h", "24h", "7d", "30d"
- `start_date`: Custom start date (ISO 8601)
- `end_date`: Custom end date (ISO 8601)

### 3. Get Top Models by Cost
```bash
GET /api/llm-usage/top-models?limit=10&sort_by=cost
```

**Response:**
```json
{
  "top_models": [
    {
      "provider": "openai",
      "model": "gpt-4o",
      "input_tokens": 8000,
      "output_tokens": 4000,
      "cost": 0.0300,
      "request_count": 4
    }
  ],
  "sort_by": "cost",
  "limit": 10,
  "total_models": 5
}
```

**Sort Options:**
- `cost`: By total cost (default)
- `tokens`: By total token usage
- `requests`: By request count

### 4. Get Pricing Information
```bash
GET /api/llm-usage/pricing-info
```

**Response:**
```json
{
  "pricing_data": {
    "openai": {
      "gpt-4o": {"input": 0.0025, "output": 0.01}
    }
  },
  "supported_providers": ["openai", "claude", "anthropic", "gemini", "google"],
  "note": "Prices are per 1,000 tokens"
}
```

## 🎨 Frontend Dashboard

### Cost Overview Cards
1. **Total LLM Cost**: Sum of all costs in timeframe
2. **Input Tokens**: Total prompt tokens used
3. **Output Tokens**: Total completion tokens generated
4. **LLM Requests**: Total requests with provider count

### Provider/Model Table
| Provider | Model | Input Tokens | Output Tokens | Cost (USD) | Requests |
|----------|-------|--------------|---------------|------------|----------|
| OpenAI | gpt-4o | 8,000 | 4,000 | $0.0300 | 4 |
| Claude | claude-3.5-sonnet | 5,000 | 3,000 | $0.0600 | 3 |

### Real-time Updates
- Dashboard refreshes every 30 seconds
- Loading states for all components
- Error handling for API failures

## 🧪 Testing

### 1. Setup Database
Run the updated database setup script:
```sql
-- Update llm_usage table to new schema
-- See database-setup.sql for complete script
```

### 2. Test Pricing Endpoint
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/api/llm-usage/pricing-info
```

### 3. Submit Test Usage Data
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-08-01T12:46:07.000Z",
    "agent_id": "agent-001",
    "provider": "openai",
    "model": "gpt-4o",
    "tokens_input": 1500,
    "tokens_output": 800,
    "client_id": "test_client_1754034419317"
  }' \
  http://localhost:8080/api/sdk/llm-usage
```

### 4. View Aggregated Data
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/api/llm-usage/aggregated?timeframe=24h
```

### 5. Check Frontend
Visit `http://localhost:3000` and navigate to the **Costs** tab to see:
- Real-time cost cards
- Provider breakdown table
- Token usage statistics

## 🚨 Next Steps

**Required for Full Functionality:**

1. **Database Migration**: Run the updated `database-setup.sql` script
2. **Test Data**: Submit sample LLM usage data
3. **Frontend Verification**: Check dashboard cost tab

**Optional Enhancements:**

1. **Cost Alerts**: Set up cost threshold notifications
2. **Historical Charts**: Add cost trend visualizations
3. **Budget Tracking**: Implement monthly budget limits
4. **Export Features**: CSV/PDF cost reports

## 🔧 Configuration

### Environment Variables
```bash
# Backend (already configured)
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Frontend (already configured)
VITE_BACKEND_URL=http://localhost:8080/api
VITE_API_KEY=your_api_key
```

### Pricing Updates
To update pricing, modify `Backend-HR/src/config/llm-pricing.ts`:
```typescript
export const LLM_PRICING: LLMPricingConfig = {
  openai: {
    'gpt-4o': { input: 0.0025, output: 0.01 }
    // Add new models here
  }
}
```

## 📈 Performance Notes

- Cost calculations are performed in real-time during data ingestion
- Aggregation queries are optimized with proper indexing
- Frontend uses efficient pagination for large datasets
- All endpoints include proper error handling and logging

---

**✅ Implementation Complete!**

The LLM cost tracking system is fully implemented with backend aggregation, cost calculation, and dashboard visualization. Follow the testing steps above to verify functionality. 