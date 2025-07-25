-- AI Agent Operations Platform Database Schema
-- For coded agents tracking (no-code agents will be added later)

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table (for multi-tenancy)
CREATE TABLE organizations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User profiles table (linked to Supabase Auth)
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id UUID REFERENCES organizations(id),
  email VARCHAR(255) NOT NULL,
  full_name VARCHAR(255),
  avatar_url TEXT,
  role VARCHAR(50) DEFAULT 'user',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Agents table (for coded agents initially)
CREATE TABLE agents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID REFERENCES organizations(id) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  agent_type VARCHAR(20) DEFAULT 'coded' CHECK (agent_type IN ('coded', 'nocode')),
  provider VARCHAR(100), -- openai, anthropic, etc.
  model VARCHAR(100), -- gpt-4, claude-3, etc.
  framework VARCHAR(100), -- langchain, llamaindex, custom, etc.
  api_key_hash VARCHAR(255), -- hashed API key for security
  endpoint_url TEXT, -- for custom endpoints
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error')),
  created_by UUID REFERENCES profiles(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_activity TIMESTAMP WITH TIME ZONE
);

-- Agent metrics table (for tracking usage and cost)
CREATE TABLE agent_metrics (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Token usage
  prompt_tokens INTEGER DEFAULT 0,
  completion_tokens INTEGER DEFAULT 0,
  total_tokens INTEGER GENERATED ALWAYS AS (prompt_tokens + completion_tokens) STORED,
  
  -- Cost tracking
  cost DECIMAL(10, 6) DEFAULT 0.00, -- in USD
  
  -- Performance metrics
  latency_ms INTEGER, -- response time in milliseconds
  success BOOLEAN DEFAULT true,
  
  -- Request metadata
  model VARCHAR(100),
  provider VARCHAR(100),
  operation VARCHAR(100), -- chat_completion, embedding, etc.
  
  -- Additional context
  metadata JSONB, -- flexible field for extra data
  
  -- Indexing for performance
  INDEX idx_agent_metrics_agent_id (agent_id),
  INDEX idx_agent_metrics_timestamp (timestamp),
  INDEX idx_agent_metrics_success (success)
);

-- Agent health table (for uptime and system metrics)
CREATE TABLE agent_health (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Health status
  status VARCHAR(20) DEFAULT 'healthy' CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'offline')),
  
  -- System metrics
  memory_usage_mb DECIMAL(10, 2), -- Memory usage in MB
  cpu_usage_percent DECIMAL(5, 2), -- CPU usage percentage
  response_time_ms INTEGER, -- Average response time
  
  -- Uptime tracking
  uptime_seconds BIGINT, -- Total uptime in seconds
  
  -- Error tracking
  error_count INTEGER DEFAULT 0,
  last_error TEXT,
  
  -- Additional metadata
  metadata JSONB,
  
  -- Indexing
  INDEX idx_agent_health_agent_id (agent_id),
  INDEX idx_agent_health_timestamp (timestamp),
  INDEX idx_agent_health_status (status)
);

-- Agent error logs table (for detailed error tracking)
CREATE TABLE agent_errors (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Error details
  error_type VARCHAR(100),
  error_message TEXT NOT NULL,
  stack_trace TEXT,
  
  -- Context
  operation VARCHAR(100),
  request_data JSONB,
  
  -- Resolution tracking
  resolved BOOLEAN DEFAULT false,
  resolved_at TIMESTAMP WITH TIME ZONE,
  resolved_by UUID REFERENCES profiles(id),
  
  -- Indexing
  INDEX idx_agent_errors_agent_id (agent_id),
  INDEX idx_agent_errors_timestamp (timestamp),
  INDEX idx_agent_errors_resolved (resolved)
);

-- Agent security events table (for security monitoring)
CREATE TABLE agent_security_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Security event details
  event_type VARCHAR(100) NOT NULL, -- 'auth_failure', 'rate_limit_exceeded', 'suspicious_activity', 'data_breach_attempt'
  severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  description TEXT NOT NULL,
  
  -- Source information
  source_ip INET,
  user_agent TEXT,
  location JSONB, -- Geolocation data
  
  -- Request details
  endpoint VARCHAR(255),
  request_method VARCHAR(10),
  request_headers JSONB,
  request_body JSONB,
  
  -- Response details
  response_status INTEGER,
  response_time_ms INTEGER,
  
  -- Threat indicators
  threat_level INTEGER DEFAULT 0, -- 0-100 scale
  threat_indicators JSONB, -- Array of threat indicators
  blocked BOOLEAN DEFAULT false,
  
  -- Investigation tracking
  investigated BOOLEAN DEFAULT false,
  investigated_at TIMESTAMP WITH TIME ZONE,
  investigated_by UUID REFERENCES profiles(id),
  investigation_notes TEXT,
  
  -- Additional context
  metadata JSONB,
  
  -- Indexing
  INDEX idx_agent_security_agent_id (agent_id),
  INDEX idx_agent_security_timestamp (timestamp),
  INDEX idx_agent_security_event_type (event_type),
  INDEX idx_agent_security_severity (severity),
  INDEX idx_agent_security_threat_level (threat_level),
  INDEX idx_agent_security_source_ip (source_ip)
);

-- Agent compliance logs table (for regulatory compliance)
CREATE TABLE agent_compliance_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Compliance details
  compliance_type VARCHAR(100) NOT NULL, -- 'gdpr', 'hipaa', 'sox', 'pci_dss'
  regulation VARCHAR(100), -- Specific regulation or standard
  requirement VARCHAR(255), -- Specific requirement being tracked
  
  -- Event details
  event_description TEXT NOT NULL,
  data_processed JSONB, -- What data was processed
  processing_purpose TEXT, -- Why was data processed
  
  -- User consent and rights
  user_consent BOOLEAN,
  consent_timestamp TIMESTAMP WITH TIME ZONE,
  user_rights_exercised TEXT, -- 'access', 'rectification', 'erasure', 'portability'
  
  -- Data handling
  data_retention_days INTEGER,
  data_location TEXT, -- Where data is stored
  encryption_status BOOLEAN DEFAULT true,
  anonymized BOOLEAN DEFAULT false,
  
  -- Audit trail
  status VARCHAR(20) DEFAULT 'compliant' CHECK (status IN ('compliant', 'non_compliant', 'under_review')),
  reviewed_by UUID REFERENCES profiles(id),
  reviewed_at TIMESTAMP WITH TIME ZONE,
  notes TEXT,
  
  -- Additional metadata
  metadata JSONB,
  
  -- Indexing
  INDEX idx_agent_compliance_agent_id (agent_id),
  INDEX idx_agent_compliance_timestamp (timestamp),
  INDEX idx_agent_compliance_type (compliance_type),
  INDEX idx_agent_compliance_status (status)
);

-- Row Level Security (RLS) policies
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_errors ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_compliance_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies (users can only access their organization's data)
CREATE POLICY "Users can access their organization's data" ON organizations
  FOR ALL USING (
    id IN (
      SELECT organization_id FROM profiles WHERE id = auth.uid()
    )
  );

CREATE POLICY "Users can access their profile" ON profiles
  FOR ALL USING (id = auth.uid() OR organization_id IN (
    SELECT organization_id FROM profiles WHERE id = auth.uid()
  ));

CREATE POLICY "Users can access their organization's agents" ON agents
  FOR ALL USING (
    organization_id IN (
      SELECT organization_id FROM profiles WHERE id = auth.uid()
    )
  );

CREATE POLICY "Users can access their organization's metrics" ON agent_metrics
  FOR ALL USING (
    agent_id IN (
      SELECT id FROM agents WHERE organization_id IN (
        SELECT organization_id FROM profiles WHERE id = auth.uid()
      )
    )
  );

CREATE POLICY "Users can access their organization's health data" ON agent_health
  FOR ALL USING (
    agent_id IN (
      SELECT id FROM agents WHERE organization_id IN (
        SELECT organization_id FROM profiles WHERE id = auth.uid()
      )
    )
  );

CREATE POLICY "Users can access their organization's error logs" ON agent_errors
  FOR ALL USING (
    agent_id IN (
      SELECT id FROM agents WHERE organization_id IN (
        SELECT organization_id FROM profiles WHERE id = auth.uid()
      )
    )
  );

CREATE POLICY "Users can access their organization's security events" ON agent_security_events
  FOR ALL USING (
    agent_id IN (
      SELECT id FROM agents WHERE organization_id IN (
        SELECT organization_id FROM profiles WHERE id = auth.uid()
      )
    )
  );

CREATE POLICY "Users can access their organization's compliance logs" ON agent_compliance_logs
  FOR ALL USING (
    agent_id IN (
      SELECT id FROM agents WHERE organization_id IN (
        SELECT organization_id FROM profiles WHERE id = auth.uid()
      )
    )
  );

-- Functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(); 