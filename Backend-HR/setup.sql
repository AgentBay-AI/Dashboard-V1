-- Enable UUID generation (Supabase: pgcrypto)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add missing columns if needed
ALTER TABLE IF EXISTS agents ADD COLUMN IF NOT EXISTS provider VARCHAR(50);
ALTER TABLE IF EXISTS agents ADD COLUMN IF NOT EXISTS model VARCHAR(100);

-- Ensure lookup table exists
CREATE TABLE IF NOT EXISTS llm_models (
  model VARCHAR(100) PRIMARY KEY,
  provider VARCHAR(50) NOT NULL
);

-- Upsert OpenAI models (lowercase keys)
INSERT INTO llm_models (model, provider) VALUES
  ('gpt-5', 'openai'),
  ('gpt-5-mini', 'openai'),
  ('gpt-4.1', 'openai'),
  ('gpt-4.1-mini', 'openai'),
  ('gpt-4.1-nano', 'openai'),
  ('gpt-4o', 'openai'),
  ('gpt-4o-mini', 'openai'),
  ('o3', 'openai'),
  ('o4-mini', 'openai'),
  ('gpt-4o-mini-2024-07-18', 'openai'),
  ('gpt-4-turbo', 'openai'),
  ('gpt-4', 'openai'),
  ('gpt-3.5-turbo', 'openai'),
  ('gpt-3.5-turbo-0125', 'openai'),
  ('text-embedding-3-small', 'openai'),
  ('text-embedding-3-large', 'openai')
ON CONFLICT (model) DO NOTHING;

-- Upsert Anthropic models
INSERT INTO llm_models (model, provider) VALUES
  ('claude-4-opus', 'anthropic'),
  ('claude-4.1-opus', 'anthropic'),
  ('claude-4-sonnet', 'anthropic'),
  ('claude-3.7-sonnet', 'anthropic'),
  ('claude-3.5-sonnet', 'anthropic'),
  ('claude-3-opus', 'anthropic'),
  ('claude-3-sonnet', 'anthropic'),
  ('claude-3-haiku', 'anthropic'),
  ('claude-2.1', 'anthropic'),
  ('claude-2.0', 'anthropic')
ON CONFLICT (model) DO NOTHING;

-- Upsert Google models
INSERT INTO llm_models (model, provider) VALUES
  ('gemini-2.5-pro', 'google'),
  ('gemini-1.5-pro', 'google'),
  ('gemini-1.5-flash', 'google'),
  ('gemini-pro', 'google'),
  ('gemini-pro-vision', 'google')
ON CONFLICT (model) DO NOTHING;

-- Drop domain tables and views but keep api_keys
DROP VIEW IF EXISTS view_organization_overview CASCADE;
DROP VIEW IF EXISTS view_success_rate CASCADE;
DROP VIEW IF EXISTS view_avg_response_time CASCADE;
DROP VIEW IF EXISTS view_quality_metrics CASCADE;

DROP TABLE IF EXISTS llm_usage CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS conversations CASCADE;
DROP TABLE IF EXISTS agent_activity CASCADE;
DROP TABLE IF EXISTS agent_status CASCADE;
DROP TABLE IF EXISTS agents CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS agent_metrics CASCADE;
DROP TABLE IF EXISTS agent_health CASCADE;
DROP TABLE IF EXISTS agent_errors CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;

-- api_keys table is preserved as-is
-- Assuming api_keys already exists with columns:
--   id, key_hash, client_id, client_name, permissions, rate_limit_per_minute, is_active, created_at, updated_at

-- Create organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    plan VARCHAR(100),
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create agents table linked to organizations and api_keys
CREATE TABLE IF NOT EXISTS agents (
    agent_id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255),
    description TEXT,
    agent_type VARCHAR(50),
    platform VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active',
    sdk_version VARCHAR(50),
    registration_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Conversations (for success rate & messages)
CREATE TABLE IF NOT EXISTS conversations (
    session_id VARCHAR(255) PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE SET NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    last_activity TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- active | ended | expired | failed
    outcome VARCHAR(50),
    quality_score VARCHAR(20),
    response_time_ms INTEGER,
    user_satisfaction INTEGER,
    metadata JSONB,
    security_flags JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Messages (for avg response time)
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) REFERENCES conversations(session_id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    content TEXT NOT NULL,
    role VARCHAR(50) NOT NULL, -- user | assistant | system
    metadata JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- LLM usage (tokens & cost)
CREATE TABLE IF NOT EXISTS llm_usage (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) REFERENCES conversations(session_id) ON DELETE SET NULL,
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE SET NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    provider VARCHAR(50) NOT NULL,
    model VARCHAR(100) NOT NULL,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    cost NUMERIC(12,6) DEFAULT 0,
    metadata JSONB,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    trace_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Agent metrics (aggregates per window)
CREATE TABLE IF NOT EXISTS agent_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    total_tokens INTEGER DEFAULT 0,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_cost NUMERIC(12,6) DEFAULT 0,
    total_requests INTEGER DEFAULT 0,
    average_latency INTEGER DEFAULT 0,
    success_rate INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Agent health (resource utilization)
CREATE TABLE IF NOT EXISTS agent_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    status VARCHAR(20) DEFAULT 'healthy',
    uptime INTEGER DEFAULT 0,
    last_ping TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    response_time INTEGER DEFAULT 0,
    error_rate INTEGER DEFAULT 0,
    cpu_usage INTEGER,
    memory_usage INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Agent errors (for activity feed)
CREATE TABLE IF NOT EXISTS agent_errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    error_type VARCHAR(100),
    error_message TEXT,
    stack_trace TEXT,
    context JSONB,
    severity VARCHAR(20) DEFAULT 'medium',
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Security events (threats/compliance)
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE SET NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    event_type VARCHAR(100) NOT NULL, -- tamper_detected | unclosed_sessions | pii_detected | ...
    severity VARCHAR(20) DEFAULT 'low',
    description TEXT,
    source_ip VARCHAR(64),
    user_agent TEXT,
    event_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Agent activity (for operations overview)
CREATE TABLE IF NOT EXISTS agent_activity (
    id BIGSERIAL PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    activity_type VARCHAR(100) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Ensure profiles has client_id for tenant mapping
ALTER TABLE IF EXISTS public.profiles
  ADD COLUMN IF NOT EXISTS client_id varchar(255);

-- Clerk integration columns
ALTER TABLE IF EXISTS public.profiles
  ADD COLUMN IF NOT EXISTS clerk_user_id varchar(255);

-- Backfill any missing client_id values
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='profiles' AND column_name='client_id') THEN
    UPDATE public.profiles
    SET client_id = 'client_' || encode(gen_random_bytes(8),'hex')
    WHERE client_id IS NULL;
  END IF;
END $$;

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_profiles_client_id ON public.profiles(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_clerk_user_id ON public.profiles(clerk_user_id);

-- Updated-at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Views for metrics
CREATE VIEW view_success_rate AS
SELECT 
    a.agent_id,
    a.client_id,
    COUNT(DISTINCT c.session_id) AS total_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'ended' THEN c.session_id END) AS successful_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'failed' THEN c.session_id END) AS failed_sessions,
    COALESCE(
      ROUND(
        (COUNT(DISTINCT CASE WHEN c.status = 'ended' THEN c.session_id END)::decimal
        / NULLIF(COUNT(DISTINCT c.session_id), 0)) * 100, 2
      ), 0
    ) AS success_rate_percent
FROM agents a
LEFT JOIN conversations c ON a.agent_id = c.agent_id
GROUP BY a.agent_id, a.client_id;

-- Optional additional views
CREATE VIEW view_avg_response_time AS
SELECT 
  a.agent_id,
  a.client_id,
  ROUND(AVG(EXTRACT(EPOCH FROM (m.created_at - c.start_time)) * 1000))::int AS avg_response_time_ms
FROM agents a
JOIN conversations c ON a.agent_id = c.agent_id
JOIN messages m ON c.session_id = m.session_id AND m.role = 'assistant'
GROUP BY a.agent_id, a.client_id;

CREATE VIEW view_quality_metrics AS
SELECT 
  a.agent_id,
  a.client_id,
  ROUND(AVG((m.metadata->>'quality_score')::numeric), 2) AS avg_quality_score
FROM agents a
JOIN conversations c ON a.agent_id = c.agent_id
JOIN messages m ON c.session_id = m.session_id
WHERE m.metadata->>'quality_score' IS NOT NULL
GROUP BY a.agent_id, a.client_id;

-- Organization overview view (agents count, sessions, monthly/yearly usage, monthly breakdown JSON)
CREATE VIEW view_organization_overview AS
WITH usage_month AS (
  SELECT a.organization_id, SUM(l.cost) AS monthly_usage
  FROM llm_usage l
  JOIN agents a ON a.agent_id = l.agent_id
  WHERE l.timestamp >= date_trunc('month', now())
  GROUP BY a.organization_id
),
usage_year AS (
  SELECT a.organization_id, SUM(l.cost) AS yearly_usage
  FROM llm_usage l
  JOIN agents a ON a.agent_id = l.agent_id
  WHERE l.timestamp >= date_trunc('year', now())
  GROUP BY a.organization_id
),
usage_breakdown AS (
  SELECT t.organization_id,
         jsonb_object_agg(t.ym, t.sum_cost) AS monthly_usage_breakdown
  FROM (
    SELECT a.organization_id,
           to_char(date_trunc('month', l.timestamp), 'YYYY-MM') AS ym,
           SUM(l.cost) AS sum_cost
    FROM llm_usage l
    JOIN agents a ON a.agent_id = l.agent_id
    WHERE l.timestamp >= (date_trunc('month', now()) - interval '11 months')
    GROUP BY a.organization_id, to_char(date_trunc('month', l.timestamp), 'YYYY-MM')
    ORDER BY a.organization_id, ym
  ) t
  GROUP BY t.organization_id
)
SELECT
  o.id,
  o.name,
  o.plan,
  o.client_id,
  o.description,
  o.created_at,
  COALESCE(a.agent_count, 0) AS agent_count,
  COALESCE(s.total_sessions, 0) AS total_sessions,
  COALESCE(m.monthly_usage, 0)::numeric AS monthly_usage,
  COALESCE(y.yearly_usage, 0)::numeric AS yearly_usage,
  COALESCE(b.monthly_usage_breakdown, '{}'::jsonb) AS monthly_usage_breakdown
FROM organizations o
LEFT JOIN (
  SELECT organization_id, COUNT(*) AS agent_count
  FROM agents
  GROUP BY organization_id
) a ON a.organization_id = o.id
LEFT JOIN (
  SELECT a.organization_id, COUNT(*) AS total_sessions
  FROM conversations c
  JOIN agents a ON a.agent_id = c.agent_id
  GROUP BY a.organization_id
) s ON s.organization_id = o.id
LEFT JOIN usage_month m ON m.organization_id = o.id
LEFT JOIN usage_year y ON y.organization_id = o.id
LEFT JOIN usage_breakdown b ON b.organization_id = o.id;

-- Optional: seed comment for admin bootstrap (no changes to api_keys here)
-- INSERT INTO api_keys (...) VALUES (...); 