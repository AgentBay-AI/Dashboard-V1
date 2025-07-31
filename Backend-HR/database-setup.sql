-- AI Agent Tracking Backend - Database Setup Script
-- Run this script in your Supabase SQL Editor

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create SDK Agents table
CREATE TABLE IF NOT EXISTS sdk_agents (
  agent_id VARCHAR(255) PRIMARY KEY,
  status VARCHAR(20) CHECK (status IN ('active', 'idle', 'error', 'maintenance')) DEFAULT 'idle',
  client_id VARCHAR(255) NOT NULL,
  last_activity TIMESTAMP WITH TIME ZONE,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for SDK Agents
CREATE INDEX IF NOT EXISTS idx_sdk_agents_status ON sdk_agents(status);
CREATE INDEX IF NOT EXISTS idx_sdk_agents_client_id ON sdk_agents(client_id);
CREATE INDEX IF NOT EXISTS idx_sdk_agents_last_activity ON sdk_agents(last_activity);

-- Create Conversations table
CREATE TABLE IF NOT EXISTS conversations (
  session_id VARCHAR(255) PRIMARY KEY,
  agent_id VARCHAR(255),
  run_id VARCHAR(255),
  user_id VARCHAR(255),
  client_id VARCHAR(255) NOT NULL,
  start_time TIMESTAMP WITH TIME ZONE,
  end_time TIMESTAMP WITH TIME ZONE NULL,
  last_activity TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) CHECK (status IN ('active', 'ended', 'expired', 'failed')) DEFAULT 'active',
  outcome VARCHAR(20) CHECK (outcome IN ('resolved', 'escalated', 'failed', 'timeout')) NULL,
  quality_score VARCHAR(20) CHECK (quality_score IN ('poor', 'fair', 'good', 'excellent')) NULL,
  response_time_ms INTEGER NULL,
  user_satisfaction DECIMAL(2,1) NULL,
  metadata JSONB DEFAULT '{}',
  security_flags JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  FOREIGN KEY (agent_id) REFERENCES sdk_agents(agent_id) ON DELETE SET NULL
);

-- Create indexes for Conversations
CREATE INDEX IF NOT EXISTS idx_conversations_agent_id ON conversations(agent_id);
CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);
CREATE INDEX IF NOT EXISTS idx_conversations_start_time ON conversations(start_time);
CREATE INDEX IF NOT EXISTS idx_conversations_client_id ON conversations(client_id);

-- Create LLM Usage table
CREATE TABLE IF NOT EXISTS llm_usage (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  provider VARCHAR(20) CHECK (provider IN ('openai', 'anthropic', 'gemini')) NOT NULL,
  model VARCHAR(100) NOT NULL,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  session_id VARCHAR(255) NULL,
  agent_id VARCHAR(255) NULL,
  client_id VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  FOREIGN KEY (session_id) REFERENCES conversations(session_id) ON DELETE SET NULL,
  FOREIGN KEY (agent_id) REFERENCES sdk_agents(agent_id) ON DELETE SET NULL
);

-- Create indexes for LLM Usage
CREATE INDEX IF NOT EXISTS idx_llm_usage_timestamp ON llm_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_llm_usage_provider_model ON llm_usage(provider, model);
CREATE INDEX IF NOT EXISTS idx_llm_usage_session_id ON llm_usage(session_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_agent_id ON llm_usage(agent_id);

-- Create Security Events table
CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY,
  event_type VARCHAR(50) CHECK (event_type IN ('tamper_detected', 'unclosed_sessions', 'pii_detected')) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  agent_id VARCHAR(255) NULL,
  client_id VARCHAR(255) NOT NULL,
  severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
  event_data JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  FOREIGN KEY (agent_id) REFERENCES sdk_agents(agent_id) ON DELETE SET NULL
);

-- Create indexes for Security Events
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_client_id ON security_events(client_id);

-- Create Compliance Audit table
CREATE TABLE IF NOT EXISTS compliance_audit (
  id BIGSERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  event_type VARCHAR(100) NOT NULL,
  compliance_flags JSONB DEFAULT '{}',
  policy_violations JSONB DEFAULT '[]',
  hash_chain VARCHAR(64),
  current_hash VARCHAR(64),
  client_id VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  FOREIGN KEY (session_id) REFERENCES conversations(session_id) ON DELETE CASCADE
);

-- Create indexes for Compliance Audit
CREATE INDEX IF NOT EXISTS idx_compliance_audit_session_id ON compliance_audit(session_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_timestamp ON compliance_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_hash_chain ON compliance_audit(hash_chain);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_event_type ON compliance_audit(event_type);

-- Create Failed Sessions table
CREATE TABLE IF NOT EXISTS failed_sessions (
  id BIGSERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL,
  agent_id VARCHAR(255),
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  client_id VARCHAR(255) NOT NULL,
  failure_reason VARCHAR(100) NOT NULL,
  error_details JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for Failed Sessions
CREATE INDEX IF NOT EXISTS idx_failed_sessions_timestamp ON failed_sessions(timestamp);
CREATE INDEX IF NOT EXISTS idx_failed_sessions_client_id ON failed_sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_failed_sessions_failure_reason ON failed_sessions(failure_reason);

-- Create API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id BIGSERIAL PRIMARY KEY,
  key_hash VARCHAR(255) UNIQUE NOT NULL,
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_name VARCHAR(255),
  created_by VARCHAR(255),
  permissions JSONB DEFAULT '["read", "write"]',
  rate_limit_per_minute INTEGER DEFAULT 1000,
  is_active BOOLEAN DEFAULT true,
  expires_at TIMESTAMP WITH TIME ZONE,
  last_used_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for API Keys
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys(client_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

-- Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
DROP TRIGGER IF EXISTS update_sdk_agents_updated_at ON sdk_agents;
CREATE TRIGGER update_sdk_agents_updated_at
    BEFORE UPDATE ON sdk_agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Enable Row Level Security (RLS) for better security
ALTER TABLE sdk_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE failed_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Create policies for RLS (optional - adjust based on your security needs)
-- These policies allow service role to access everything

CREATE POLICY "Service role can access sdk_agents" ON sdk_agents
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access conversations" ON conversations
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access llm_usage" ON llm_usage
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access security_events" ON security_events
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access compliance_audit" ON compliance_audit
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access failed_sessions" ON failed_sessions
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role can access api_keys" ON api_keys
  FOR ALL USING (auth.role() = 'service_role');

-- Insert a sample API key for testing (optional)
-- Generate this using the setup-api-key.js script for production
/*
INSERT INTO api_keys (key_hash, client_id, client_name, permissions, rate_limit_per_minute, is_active) 
VALUES (
  'sample_hash_replace_with_real_hash',
  'test_client_123',
  'Test Development Client',
  '["read", "write"]',
  1000,
  true
) ON CONFLICT (client_id) DO NOTHING;
*/

-- Verify tables were created
SELECT 
  schemaname, 
  tablename, 
  tableowner 
FROM pg_tables 
WHERE schemaname = 'public' 
  AND tablename IN (
    'sdk_agents', 
    'conversations', 
    'llm_usage', 
    'security_events', 
    'compliance_audit', 
    'failed_sessions', 
    'api_keys'
  )
ORDER BY tablename;

-- Display table counts
SELECT 'sdk_agents' as table_name, COUNT(*) as record_count FROM sdk_agents
UNION ALL
SELECT 'conversations', COUNT(*) FROM conversations
UNION ALL
SELECT 'llm_usage', COUNT(*) FROM llm_usage
UNION ALL
SELECT 'security_events', COUNT(*) FROM security_events
UNION ALL
SELECT 'compliance_audit', COUNT(*) FROM compliance_audit
UNION ALL
SELECT 'failed_sessions', COUNT(*) FROM failed_sessions
UNION ALL
SELECT 'api_keys', COUNT(*) FROM api_keys;

-- Success message
SELECT 'AI Agent Tracking Database Setup Complete! 🎉' as status; 