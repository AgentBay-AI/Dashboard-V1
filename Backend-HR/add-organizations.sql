-- Create organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'Basic',
    client_id VARCHAR(255) NOT NULL REFERENCES api_keys(client_id),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add organization_id to agents table if not exists
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS organization_id BIGINT REFERENCES organizations(id);

-- Create trigger for organizations updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample organizations
INSERT INTO organizations (name, plan, client_id, metadata) VALUES
('TechCorp Inc', 'Enterprise', 'current_frontend_client', '{"description": "Technology company", "email": "contact@techcorp.com", "type": "enterprise"}'),
('SalesForce Ltd', 'Professional', 'current_frontend_client', '{"description": "Sales automation company", "email": "contact@salesforce.com", "type": "professional"}'),
('HR Solutions', 'Basic', 'current_frontend_client', '{"description": "Human resources company", "email": "contact@hrsolutions.com", "type": "startup"}'),
('MarketingPro', 'Professional', 'current_frontend_client', '{"description": "Marketing agency", "email": "contact@marketingpro.com", "type": "professional"}')
ON CONFLICT DO NOTHING;

-- Update existing agents with organization IDs
UPDATE agents
SET organization_id = (SELECT id FROM organizations WHERE name = 'TechCorp Inc' LIMIT 1)
WHERE agent_id = 'test-agent-1' AND organization_id IS NULL;

UPDATE agents
SET organization_id = (SELECT id FROM organizations WHERE name = 'SalesForce Ltd' LIMIT 1)
WHERE agent_id = 'test-agent-2' AND organization_id IS NULL;

-- Create view to list all agents under organizations
CREATE OR REPLACE VIEW view_organization_agents AS
SELECT
    o.id as organization_id,
    o.name as organization_name,
    o.plan as organization_plan,
    o.client_id,
    a.agent_id,
    a.status as agent_status,
    a.sdk_version,
    a.metadata as agent_metadata,
    a.registration_time,
    COUNT(c.session_id) as total_sessions,
    COUNT(CASE WHEN c.status = 'completed' THEN 1 END) as completed_sessions,
    COALESCE(SUM(l.tokens_input + l.tokens_output), 0) as total_tokens,
    COALESCE(SUM(
        CASE
            WHEN l.model LIKE '%gpt-4%' THEN (l.tokens_input + l.tokens_output) * 0.00003
            WHEN l.model LIKE '%gpt-3.5%' THEN (l.tokens_input + l.tokens_output) * 0.000002
            WHEN l.model LIKE '%claude%' THEN (l.tokens_input + l.tokens_output) * 0.000015
            ELSE (l.tokens_input + l.tokens_output) * 0.00001
        END
    ), 0) as estimated_cost
FROM organizations o
LEFT JOIN agents a ON a.organization_id = o.id
LEFT JOIN conversations c ON c.agent_id = a.agent_id
LEFT JOIN llm_usage l ON l.agent_id = a.agent_id
GROUP BY o.id, o.name, o.plan, o.client_id, a.agent_id, a.status, a.sdk_version, a.metadata, a.registration_time
ORDER BY o.name, a.agent_id;

-- Create view for organization metrics summary
CREATE OR REPLACE VIEW view_organization_metrics AS
SELECT
    o.id as organization_id,
    o.name,
    o.plan,
    o.client_id,
    o.metadata,
    COUNT(DISTINCT a.agent_id) as agent_count,
    COUNT(DISTINCT CASE WHEN a.status = 'active' THEN a.agent_id END) as active_agents,
    COUNT(DISTINCT c.session_id) as total_sessions,
    COALESCE(SUM(l.tokens_input + l.tokens_output), 0) as total_tokens,
    COALESCE(SUM(
        CASE
            WHEN l.model LIKE '%gpt-4%' THEN (l.tokens_input + l.tokens_output) * 0.00003
            WHEN l.model LIKE '%gpt-3.5%' THEN (l.tokens_input + l.tokens_output) * 0.000002
            WHEN l.model LIKE '%claude%' THEN (l.tokens_input + l.tokens_output) * 0.000015
            ELSE (l.tokens_input + l.tokens_output) * 0.00001
        END
    ), 0) as monthly_usage
FROM organizations o
LEFT JOIN agents a ON a.organization_id = o.id
LEFT JOIN conversations c ON c.agent_id = a.agent_id
LEFT JOIN llm_usage l ON l.agent_id = a.agent_id
GROUP BY o.id, o.name, o.plan, o.client_id, o.metadata
ORDER BY o.name; 