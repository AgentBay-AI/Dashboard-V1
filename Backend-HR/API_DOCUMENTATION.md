# AI Agent Tracking Backend API Documentation

This backend API provides comprehensive tracking, monitoring, and management capabilities for AI agents through our Python SDK.

## 🚀 Quick Start

### Base URL
```
Production: https://your-api-domain.com
Development: http://localhost:8080
```

### Authentication
All endpoints require Bearer token authentication:
```bash
Authorization: Bearer YOUR_API_KEY
```

### Get API Key
Contact your administrator or use the admin endpoint:
```bash
POST /api/admin/api-keys
Content-Type: application/json

{
  "client_id": "your_client_id",
  "client_name": "Your Organization",
  "permissions": ["read", "write"],
  "rate_limit_per_minute": 1000
}
```

## 📊 Endpoint Overview

| Category | Endpoint | Description |
|----------|----------|-------------|
| **Agents** | `POST /api/sdk/agents/register` | Register a new agent |
| **Agents** | `POST /api/sdk/agents/status` | Update agent status |
| **Agents** | `GET /api/sdk/agents/overview` | Get agents overview |
| **Conversations** | `POST /api/sdk/conversations/start` | Start conversation tracking |
| **Conversations** | `POST /api/sdk/conversations/end` | End conversation |
| **Conversations** | `POST /api/sdk/conversations/resume` | Resume conversation |
| **Conversations** | `GET /api/sdk/conversations/{id}` | Get conversation details |
| **Security** | `POST /api/sdk/security/metrics` | Report security metrics |
| **Security** | `POST /api/sdk/security/tamper` | Report tamper detection |
| **LLM** | `POST /api/sdk/llm-usage` | Track LLM usage |
| **Compliance** | `POST /api/sdk/compliance/audit` | Log compliance event |
| **Dashboard** | `GET /api/dashboard/overview` | Get dashboard overview |

## 🤖 Agent Operations

### Register Agent
```bash
POST /api/sdk/agents/register
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "agent_id": "agent_123",
  "timestamp": "2025-01-13T10:30:00Z",
  "client_id": "sdk_client_xyz",
  "metadata": {
    "version": "1.0.0",
    "environment": "production",
    "capabilities": ["chat", "analysis"]
  }
}
```

**Response:**
```json
{
  "message": "Agent registered successfully",
  "agent": {
    "agent_id": "agent_123",
    "status": "active",
    "client_id": "sdk_client_xyz",
    "last_activity": "2025-01-13T10:30:00Z",
    "metadata": {...},
    "created_at": "2025-01-13T10:30:00Z"
  },
  "timestamp": "2025-01-13T10:30:00Z"
}
```

### Update Agent Status
```bash
POST /api/sdk/agents/status
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "agent_id": "agent_123",
  "status": "active",
  "timestamp": "2025-01-13T10:30:00Z",
  "client_id": "sdk_client_xyz",
  "metadata": {
    "cpu_usage": 45.2,
    "memory_usage": 1024,
    "last_activity": "2025-01-13T10:29:00Z"
  }
}
```

### Get Agents Overview
```bash
GET /api/sdk/agents/overview
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "total_agents": 50,
  "active_agents": 35,
  "idle_agents": 10,
  "error_agents": 5,
  "maintenance_agents": 0,
  "last_updated": "2025-01-13T10:30:00Z"
}
```

## 💬 Conversation Tracking

### Start Conversation
```bash
POST /api/sdk/conversations/start
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "session_id": "session_abc123",
  "agent_id": "agent_123",
  "timestamp": "2025-01-13T10:30:00Z",
  "client_id": "sdk_client_xyz",
  "run_id": "run_456",
  "user_id": "user_789",
  "metadata": {
    "conversation_type": "customer_support",
    "channel": "web_chat",
    "priority": "normal"
  },
  "security_flags": {
    "tamper_detected": false,
    "pii_detected": false,
    "compliance_violation": false
  }
}
```

### End Conversation
```bash
POST /api/sdk/conversations/end
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "session_id": "session_abc123",
  "timestamp": "2025-01-13T10:35:00Z",
  "client_id": "sdk_client_xyz",
  "outcome": "resolved",
  "quality_score": "excellent",
  "response_time_ms": 2500,
  "user_satisfaction": 4.5,
  "metadata": {
    "resolution_steps": 3,
    "escalation_reason": null,
    "final_status": "customer_satisfied"
  }
}
```

### Get Conversation Details
```bash
GET /api/sdk/conversations/session_abc123
Authorization: Bearer YOUR_API_KEY
```

## 🔐 Security Endpoints

### Report Security Metrics
```bash
POST /api/sdk/security/metrics
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "event_type": "unclosed_sessions",
  "timestamp": "2025-01-13T10:30:00Z",
  "agent_id": "agent_123",
  "client_id": "sdk_client_xyz",
  "unclosed_count": 5,
  "unclosed_sessions": [
    {
      "session_id": "session_1",
      "start_time": "2025-01-13T08:00:00Z",
      "last_activity": "2025-01-13T09:00:00Z"
    }
  ]
}
```

### Report Tamper Detection
```bash
POST /api/sdk/security/tamper
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "event_type": "tamper_detected",
  "timestamp": "2025-01-13T10:30:00Z",
  "agent_id": "agent_123",
  "client_id": "sdk_client_xyz",
  "sdk_version": "1.2.1",
  "checksum_expected": "abc123...",
  "checksum_actual": "xyz789...",
  "modified_files": ["AgentOper.py", "security.py"],
  "severity": "high"
}
```

## 📊 LLM Usage Tracking

```bash
POST /api/sdk/llm-usage
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "timestamp": "2025-01-13T10:30:00Z",
  "provider": "openai",
  "model": "gpt-4",
  "prompt_tokens": 150,
  "completion_tokens": 75,
  "total_tokens": 225,
  "session_id": "session_abc123",
  "agent_id": "agent_123"
}
```

## 📋 Compliance Endpoints

### Compliance Audit
```bash
POST /api/sdk/compliance/audit
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "audit_entry": {
    "session_id": "session_abc123",
    "timestamp": "2025-01-13T10:30:00Z",
    "event_type": "conversation_start",
    "compliance_flags": {
      "gdpr_scope": true,
      "hipaa_scope": false,
      "pii_detected": false,
      "phi_detected": false,
      "cross_border_transfer": false
    },
    "policy_violations": [],
    "data_sent_to": "backend_server_eu",
    "retention_policy": "30_days",
    "user_acknowledged": false
  },
  "hash_chain": "previous_hash_abc123",
  "current_hash": "current_hash_def456"
}
```

### Compliance Acknowledgment
```bash
POST /api/sdk/compliance/acknowledgment
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "session_id": "session_abc123",
  "policy_type": "gdpr_cross_border",
  "acknowledged_by": "developer_id_123",
  "acknowledgment_reason": "Explicit user consent obtained",
  "timestamp": "2025-01-13T10:30:00Z"
}
```

## 📈 Dashboard

### Get Dashboard Overview
```bash
GET /api/dashboard/overview
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "agents": {
    "total": 50,
    "active": 35,
    "idle": 10,
    "error": 5,
    "maintenance": 0
  },
  "conversations": {
    "total_today": 1250,
    "active": 45,
    "avg_response_time_ms": 2300,
    "avg_quality_score": "good"
  },
  "llm_usage": {
    "total_tokens_today": 150000,
    "cost_estimate_usd": 45.50,
    "top_models": ["gpt-4", "claude-3", "gemini-pro"]
  },
  "security": {
    "tamper_events": 0,
    "pii_detections": 3,
    "unclosed_sessions": 5
  },
  "last_updated": "2025-01-13T10:30:00Z"
}
```

## 🔧 Error Handling

### Standard Error Response
```json
{
  "error": "Error Type",
  "message": "Detailed error message",
  "details": "Additional context (optional)",
  "timestamp": "2025-01-13T10:30:00Z"
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid API key)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate resource)
- `429` - Rate Limited
- `500` - Internal Server Error

## 🚦 Rate Limiting

- Default: 1000 requests per minute per API key
- Rate limit headers included in responses:
  ```
  X-RateLimit-Limit: 1000
  X-RateLimit-Remaining: 999
  X-RateLimit-Reset: 1642012800
  ```

## 🔒 Security

### Authentication
- Bearer token authentication required
- API keys are hashed and stored securely
- Keys can be revoked/deactivated

### Rate Limiting
- Per-client configurable rate limits
- Automatic cleanup of expired rate limit data

### Input Validation
- All payloads validated with Zod schemas
- SQL injection prevention
- Input sanitization

## 🏗️ Infrastructure

### Database Schema
The API uses the following main tables:
- `sdk_agents` - Agent registrations and status
- `conversations` - Conversation tracking
- `llm_usage` - LLM usage metrics
- `security_events` - Security events and alerts
- `compliance_audit` - Compliance audit trail
- `failed_sessions` - Failed session tracking
- `api_keys` - API key management

### Monitoring
- Request/response logging
- Performance metrics
- Error rate monitoring
- Database query performance tracking

## 📝 Development

### Local Setup
1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables
4. Run: `npm run dev`

### Environment Variables
```bash
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_key
PORT=8080
NODE_ENV=development
```

### Testing
```bash
# Run tests
npm test

# Test specific endpoint
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     http://localhost:8080/api/sdk/agents/overview
```

## 🚀 Deployment

### Production Checklist
- [ ] Set up production database with required tables
- [ ] Configure SSL/TLS certificates
- [ ] Set up monitoring and alerting
- [ ] Configure backup and recovery
- [ ] Set production environment variables
- [ ] Test all endpoints with production API keys
- [ ] Set up rate limiting
- [ ] Configure logging and monitoring

### Docker Deployment
```bash
# Build image
npm run docker:build

# Run container
npm run docker:run
```

## 📞 Support

For technical support, API questions, or to request additional features:
- GitHub Issues: [Create Issue](https://github.com/your-repo/ai-hr-agent/issues)
- Email: support@your-domain.com
- Documentation: [Full Docs](https://docs.your-domain.com)

---

**Last Updated:** January 13, 2025  
**API Version:** 1.0.0  
**Status:** Production Ready 