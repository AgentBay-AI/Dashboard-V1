-- Clean AI Agent Database Setup Script
-- Run this script in your Supabase SQL Editor

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop everything in the correct order to avoid dependencies
DROP VIEW IF EXISTS view_active_conversations CASCADE;
DROP VIEW IF EXISTS view_quality_metrics CASCADE;
DROP VIEW IF EXISTS view_avg_response_time CASCADE;
DROP VIEW IF EXISTS view_success_rate CASCADE;

DROP TRIGGER IF EXISTS update_agents_updated_at ON agents CASCADE;
DROP TRIGGER IF EXISTS update_conversations_updated_at ON conversations CASCADE;

DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS conversations CASCADE;
DROP TABLE IF EXISTS llm_usage CASCADE;
DROP TABLE IF EXISTS agent_activity CASCADE;
DROP TABLE IF EXISTS agent_status CASCADE;
DROP TABLE IF EXISTS agents CASCADE;

-- Drop any legacy tables that might exist
DROP TABLE IF EXISTS sdk_agents CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;
DROP TABLE IF EXISTS compliance_audit CASCADE;
DROP TABLE IF EXISTS failed_sessions CASCADE;

DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
DROP FUNCTION IF EXISTS increment_messages() CASCADE;

-- Create update function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create increment_messages function
CREATE OR REPLACE FUNCTION increment_messages()
RETURNS trigger AS $$
BEGIN
    UPDATE conversations 
    SET total_messages = total_messages + 1 
    WHERE session_id = NEW.session_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create agents table
CREATE TABLE agents (
  agent_id VARCHAR(255) PRIMARY KEY,
  registration_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  client_id VARCHAR(255) NOT NULL,
  sdk_version VARCHAR(50),
  metadata JSONB DEFAULT '{}',
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create agent_status table
CREATE TABLE agent_status (
  id BIGSERIAL PRIMARY KEY,
  agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  status VARCHAR(50) NOT NULL CHECK (status IN ('active', 'idle', 'busy', 'error', 'offline', 'initializing')),
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  previous_status VARCHAR(50),
  metadata JSONB DEFAULT '{}',
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create agent_activity table
CREATE TABLE agent_activity (
  id BIGSERIAL PRIMARY KEY,
  agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  details JSONB DEFAULT '{}',
  duration INTEGER,
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create conversations table
CREATE TABLE conversations (
  session_id VARCHAR(255) PRIMARY KEY,
  agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'failed', 'expired', 'evicted', 'resumed')),
  start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  end_time TIMESTAMP WITH TIME ZONE,
  total_messages INTEGER DEFAULT 0,
  quality_score DECIMAL(3,2) CHECK (quality_score >= 1 AND quality_score <= 5),
  metadata JSONB DEFAULT '{}',
  security_flags JSONB DEFAULT '{}',
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create messages table
CREATE TABLE messages (
  id BIGSERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL REFERENCES conversations(session_id) ON DELETE CASCADE,
  agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  message_type VARCHAR(50) NOT NULL CHECK (message_type IN ('user', 'assistant', 'system')),
  content TEXT,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  response_time_ms INTEGER,
  token_count INTEGER,
  metadata JSONB DEFAULT '{}',
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create llm_usage table
CREATE TABLE llm_usage (
  id BIGSERIAL PRIMARY KEY,
  agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  session_id VARCHAR(255) REFERENCES conversations(session_id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  provider VARCHAR(100) NOT NULL,
  model VARCHAR(100) NOT NULL,
  tokens_input INTEGER NOT NULL DEFAULT 0,
  tokens_output INTEGER NOT NULL DEFAULT 0,
  metadata JSONB DEFAULT '{}',
  trace_id VARCHAR(255),
  span_id VARCHAR(255),
  trace_context JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_agents_client_id ON agents(client_id);
CREATE INDEX IF NOT EXISTS idx_agent_status_agent_id ON agent_status(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_status_timestamp ON agent_status(timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_activity_agent_id ON agent_activity(agent_id);
CREATE INDEX IF NOT EXISTS idx_conversations_agent_id ON conversations(agent_id);
CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);
CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_agent_id ON messages(agent_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_agent_id ON llm_usage(agent_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_client_id ON llm_usage(client_id);

-- Create triggers
CREATE TRIGGER update_agents_updated_at 
  BEFORE UPDATE ON agents 
  FOR EACH ROW 
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversations_updated_at 
  BEFORE UPDATE ON conversations 
  FOR EACH ROW 
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER increment_messages_count
  AFTER INSERT ON messages
  FOR EACH ROW
  EXECUTE FUNCTION increment_messages();

-- Insert test data
INSERT INTO agents (agent_id, client_id, sdk_version, metadata) VALUES
('agent_001', 'test_client_1754071141650', '1.0.0', '{"version": "1.0.0", "environment": "development"}'),
('agent_002', 'test_client_1754071141650', '1.0.0', '{"version": "1.0.0", "environment": "production"}'),
('agent_003', 'test_client_1754071141650', '1.1.0', '{"version": "1.1.0", "environment": "staging"}');

INSERT INTO agent_status (agent_id, client_id, status, previous_status, metadata) VALUES
('agent_001', 'test_client_1754071141650', 'active', 'idle', '{"cpu_usage": 45, "memory_usage": 60}'),
('agent_002', 'test_client_1754071141650', 'busy', 'active', '{"cpu_usage": 80, "memory_usage": 75}'),
('agent_003', 'test_client_1754071141650', 'idle', 'active', '{"cpu_usage": 20, "memory_usage": 40}');

INSERT INTO conversations (session_id, agent_id, client_id, status, start_time, end_time, total_messages, quality_score, metadata) VALUES
('session_001', 'agent_001', 'test_client_1754071141650', 'completed', CURRENT_TIMESTAMP - INTERVAL '2 hours', CURRENT_TIMESTAMP - INTERVAL '1 hour 30 minutes', 15, 4.5, '{"user_satisfaction": "high", "resolution": "complete"}'),
('session_002', 'agent_001', 'test_client_1754071141650', 'completed', CURRENT_TIMESTAMP - INTERVAL '1 hour', CURRENT_TIMESTAMP - INTERVAL '30 minutes', 8, 3.8, '{"user_satisfaction": "medium", "resolution": "partial"}'),
('session_003', 'agent_002', 'test_client_1754071141650', 'active', CURRENT_TIMESTAMP - INTERVAL '15 minutes', NULL, 5, NULL, '{"in_progress": true}'),
('session_004', 'agent_002', 'test_client_1754071141650', 'failed', CURRENT_TIMESTAMP - INTERVAL '3 hours', CURRENT_TIMESTAMP - INTERVAL '2 hours 45 minutes', 3, NULL, '{"error": "timeout", "reason": "user_disconnected"}'),
('session_005', 'agent_003', 'test_client_1754071141650', 'completed', CURRENT_TIMESTAMP - INTERVAL '4 hours', CURRENT_TIMESTAMP - INTERVAL '3 hours 30 minutes', 12, 4.2, '{"user_satisfaction": "high", "resolution": "complete"}'),
('session_006', 'agent_001', 'test_client_1754071141650', 'active', CURRENT_TIMESTAMP - INTERVAL '5 minutes', NULL, 2, NULL, '{"in_progress": true}');

INSERT INTO messages (session_id, agent_id, message_type, content, response_time_ms, token_count, metadata) VALUES
('session_001', 'agent_001', 'user', 'Hello, I need help with my account', NULL, 12, '{}'),
('session_001', 'agent_001', 'assistant', 'I can help you with your account. What specific issue are you facing?', 850, 18, '{"confidence": 0.95}'),
('session_001', 'agent_001', 'user', 'I cannot log in', NULL, 8, '{}'),
('session_001', 'agent_001', 'assistant', 'Let me help you troubleshoot the login issue', 920, 15, '{"confidence": 0.92}'),
('session_002', 'agent_001', 'user', 'What are your business hours?', NULL, 10, '{}'),
('session_002', 'agent_001', 'assistant', 'Our business hours are Monday to Friday, 9 AM to 6 PM EST', 650, 20, '{"confidence": 0.98}'),
('session_003', 'agent_002', 'user', 'I need technical support', NULL, 9, '{}'),
('session_003', 'agent_002', 'assistant', 'I can provide technical support. What technical issue are you experiencing?', 1200, 22, '{"confidence": 0.87}'),
('session_005', 'agent_003', 'user', 'How do I reset my password?', NULL, 11, '{}'),
('session_005', 'agent_003', 'assistant', 'I can guide you through the password reset process', 750, 16, '{"confidence": 0.94}'),
('session_006', 'agent_001', 'user', 'Quick question about billing', NULL, 9, '{}'),
('session_006', 'agent_001', 'assistant', 'I am happy to help with billing questions. What would you like to know?', 800, 19, '{"confidence": 0.91}');

INSERT INTO llm_usage (agent_id, client_id, session_id, provider, model, tokens_input, tokens_output, metadata) VALUES
('agent_001', 'test_client_1754071141650', 'session_001', 'openai', 'gpt-4', 120, 180, '{"cost_usd": 0.0456, "temperature": 0.7}'),
('agent_001', 'test_client_1754071141650', 'session_002', 'openai', 'gpt-4', 80, 120, '{"cost_usd": 0.0300, "temperature": 0.7}'),
('agent_002', 'test_client_1754071141650', 'session_003', 'anthropic', 'claude-3-sonnet', 150, 200, '{"cost_usd": 0.0525, "temperature": 0.6}'),
('agent_002', 'test_client_1754071141650', 'session_004', 'openai', 'gpt-3.5-turbo', 60, 90, '{"cost_usd": 0.0090, "temperature": 0.8}'),
('agent_003', 'test_client_1754071141650', 'session_005', 'openai', 'gpt-4', 100, 150, '{"cost_usd": 0.0375, "temperature": 0.7}'),
('agent_001', 'test_client_1754071141650', 'session_006', 'openai', 'gpt-4', 70, 110, '{"cost_usd": 0.0270, "temperature": 0.7}');

-- Now create the views after all tables and data exist
CREATE OR REPLACE VIEW view_success_rate AS
SELECT 
  agent_id,
  COUNT(*) AS total_sessions,
  SUM(CASE WHEN quality_score IS NOT NULL THEN 1 ELSE 0 END) AS successful_sessions,
  SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_sessions,
  ROUND(
    (SUM(CASE WHEN quality_score IS NOT NULL THEN 1 ELSE 0 END)::decimal /
     NULLIF(COUNT(*), 0)) * 100, 2
  ) AS success_rate_percent,
  MAX(updated_at) AS last_updated
FROM conversations
GROUP BY agent_id;

CREATE OR REPLACE VIEW view_avg_response_time AS
SELECT
  m.agent_id,
  AVG(m.response_time_ms) AS avg_response_time_ms,
  COUNT(m.response_time_ms) AS response_count
FROM messages m
WHERE m.response_time_ms IS NOT NULL
GROUP BY m.agent_id;

CREATE OR REPLACE VIEW view_quality_metrics AS
SELECT
  agent_id,
  AVG(quality_score) AS avg_quality_score,
  COUNT(quality_score) AS rated_sessions,
  MIN(quality_score) AS min_quality_score,
  MAX(quality_score) AS max_quality_score
FROM conversations
WHERE quality_score IS NOT NULL
GROUP BY agent_id;

CREATE OR REPLACE VIEW view_active_conversations AS
SELECT
  c.session_id,
  c.agent_id,
  c.status,
  c.start_time,
  c.total_messages,
  COALESCE(msg.last_message_time, c.start_time) AS last_message_time,
  EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - c.start_time)) / 60 AS duration_minutes
FROM conversations c
LEFT JOIN (
  SELECT 
    session_id, 
    MAX(timestamp) AS last_message_time
  FROM messages 
  GROUP BY session_id
) msg ON c.session_id = msg.session_id
WHERE c.status = 'active';

-- Verify setup
SELECT 'Database setup completed successfully!' as status; 