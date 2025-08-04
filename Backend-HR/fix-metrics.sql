-- Create the missing metrics views
CREATE OR REPLACE VIEW view_success_rate AS
SELECT 
    a.agent_id,
    a.client_id,
    COUNT(DISTINCT c.session_id) as total_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'completed' THEN c.session_id END) as successful_sessions,
    COUNT(DISTINCT CASE WHEN c.status = 'failed' THEN c.session_id END) as failed_sessions,
    CASE 
        WHEN COUNT(DISTINCT c.session_id) = 0 THEN NULL
        ELSE (COUNT(DISTINCT CASE WHEN c.status = 'completed' THEN c.session_id END)::DECIMAL / COUNT(DISTINCT c.session_id) * 100)
    END as success_rate_percent
FROM agents a
LEFT JOIN conversations c ON a.agent_id = c.agent_id
GROUP BY a.agent_id, a.client_id;

CREATE OR REPLACE VIEW view_avg_response_time AS
SELECT 
    a.agent_id,
    a.client_id,
    AVG(EXTRACT(EPOCH FROM (c.end_time - c.start_time)) * 1000)::DECIMAL(10,2) as avg_response_time_ms,
    MIN(EXTRACT(EPOCH FROM (c.end_time - c.start_time)) * 1000)::DECIMAL(10,2) as min_response_time_ms,
    MAX(EXTRACT(EPOCH FROM (c.end_time - c.start_time)) * 1000)::DECIMAL(10,2) as max_response_time_ms
FROM agents a
LEFT JOIN conversations c ON a.agent_id = c.agent_id
WHERE c.end_time IS NOT NULL
GROUP BY a.agent_id, a.client_id;

CREATE OR REPLACE VIEW view_quality_metrics AS
SELECT 
    a.agent_id,
    a.client_id,
    AVG(CASE 
        WHEN jsonb_typeof(m.metadata->'quality_score') = 'number' 
        THEN (m.metadata->>'quality_score')::DECIMAL 
        ELSE NULL 
    END)::DECIMAL(10,2) as avg_quality_score,
    COUNT(CASE 
        WHEN jsonb_typeof(m.metadata->'quality_score') = 'number' 
        THEN 1 
        ELSE NULL 
    END) as rated_sessions
FROM agents a
LEFT JOIN conversations c ON a.agent_id = c.agent_id
LEFT JOIN messages m ON c.session_id = m.session_id
WHERE m.metadata ? 'quality_score'
GROUP BY a.agent_id, a.client_id; 