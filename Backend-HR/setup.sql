-- Drop existing tables in correct order
DROP TABLE IF EXISTS llm_usage CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS conversations CASCADE;
DROP TABLE IF EXISTS agent_activity CASCADE;
DROP TABLE IF EXISTS agent_status CASCADE;
DROP TABLE IF EXISTS agents CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;

-- Drop existing views
DROP VIEW IF EXISTS view_success_rate CASCADE;
DROP VIEW IF EXISTS view_avg_response_time CASCADE;
DROP VIEW IF EXISTS view_quality_metrics CASCADE;

-- Create api_keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '["read", "write"]'::jsonb,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 1000,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create agents table
CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    capabilities TEXT,
    llm_providers JSONB,
    platform VARCHAR(100),
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active',
    UNIQUE(client_id, name)
);

-- Create agent status table
CREATE TABLE IF NOT EXISTS agent_status (
    agent_id VARCHAR(255) PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'online',
    last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    UNIQUE(agent_id, client_id)
);

-- Create agent activity table
CREATE TABLE IF NOT EXISTS agent_activity (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES agents(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    activity_type VARCHAR(50) NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create conversations table
CREATE TABLE IF NOT EXISTS conversations (
    session_id VARCHAR(255) PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES agents(agent_id),
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    metadata JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create messages table
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) REFERENCES conversations(session_id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    content TEXT NOT NULL,
    role VARCHAR(50) NOT NULL,
    metadata JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create llm_usage table
CREATE TABLE IF NOT EXISTS llm_usage (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) REFERENCES conversations(session_id),
    agent_id VARCHAR(255) REFERENCES agents(agent_id),
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    model VARCHAR(100) NOT NULL,
    tokens_input INTEGER NOT NULL,
    tokens_output INTEGER NOT NULL,
    metadata JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversations_updated_at
    BEFORE UPDATE ON conversations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create views for metrics
CREATE VIEW view_success_rate AS
SELECT 
    a.agent_id,
    a.client_id,
    COUNT(DISTINCT c.session_id) as total_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'completed' THEN c.session_id END) as successful_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'failed' THEN c.session_id END) as failed_sessions,
    CAST(
        CAST(COUNT(DISTINCT CASE WHEN c.status = 'completed' THEN c.session_id END) AS DECIMAL(10,2)) / 
        NULLIF(COUNT(DISTINCT c.session_id), 0) * 100 
    AS DECIMAL(10,2)) as success_rate_percent
FROM agents a
LEFT JOIN conversations c ON a.agent_id = c.agent_id
GROUP BY a.agent_id, a.client_id;

CREATE VIEW view_avg_response_time AS
SELECT 
    a.agent_id,
    a.client_id,
    CAST(
        AVG(EXTRACT(EPOCH FROM (messages.created_at - conversations.start_time)) * 1000)
    AS DECIMAL(10,2)) as avg_response_time_ms
FROM agents a
LEFT JOIN conversations ON a.agent_id = conversations.agent_id
LEFT JOIN messages ON conversations.session_id = messages.session_id
WHERE messages.role = 'assistant'
GROUP BY a.agent_id, a.client_id;

CREATE VIEW view_quality_metrics AS
SELECT 
    a.agent_id,
    a.client_id,
    CAST(
        AVG(CAST(messages.metadata->>'quality_score' AS DECIMAL(10,2)))
    AS DECIMAL(10,2)) as avg_quality_score
FROM agents a
LEFT JOIN conversations ON a.agent_id = conversations.agent_id
LEFT JOIN messages ON conversations.session_id = messages.session_id
WHERE messages.metadata->>'quality_score' IS NOT NULL
GROUP BY a.agent_id, a.client_id;

-- Insert API keys
INSERT INTO api_keys (
    key_hash,
    client_id,
    client_name,
    permissions,
    rate_limit_per_minute,
    is_active
) VALUES (
    '8cf05c8c531b3a56fe9537eccbd5b3282155c1ef779186e9c6df8a9c51072c3b',  -- Hash of 3301f4d913aa2e2a928a3686bdc17e33
    'current_frontend_client',
    'Current Frontend Client',
    '["read", "write", "sdk"]'::jsonb,
    5000,
    true
); 