import { testConnection, supabase } from './supabase';
import { logger } from '../utils/logger';

export async function initializeDatabase() {
  try {
    logger.info('🚀 Initializing database...');
    
    // Test connection with timeout
    const connectionPromise = testConnection();
    const timeoutPromise = new Promise<boolean>((_, reject) => 
      setTimeout(() => reject(new Error('Connection timeout')), 10000)
    );
    
    const connectionSuccessful = await Promise.race([connectionPromise, timeoutPromise]);
    
    if (!connectionSuccessful) {
      logger.warn('⚠️  Database connection failed, using empty mode');
      logger.info('📊 Backend will serve empty data until database is connected');
      return false;
    }

    // Create required tables if they don't exist
    await createAgentTrackingTables();

    logger.info('✅ Database connection successful');
    logger.info('📊 Database is ready with AI Agent tracking tables');
    logger.info('🎉 Database initialization complete - showing empty state');
    return true;
  } catch (error: any) {
    logger.error('❌ Database initialization failed:', error.message);
    logger.warn('⚠️  Falling back to empty mode - all APIs will return empty data');
    return false;
  }
}

async function createAgentTrackingTables() {
  try {
    logger.info('📦 Creating AI Agent tracking tables...');

    // Create SDK Agents table (different from existing agents table)
    const agentsQuery = `
      CREATE TABLE IF NOT EXISTS sdk_agents (
        agent_id VARCHAR(255) PRIMARY KEY,
        status VARCHAR(20) CHECK (status IN ('active', 'idle', 'error', 'maintenance')) DEFAULT 'idle',
        client_id VARCHAR(255) NOT NULL,
        last_activity TIMESTAMP WITH TIME ZONE,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      
      CREATE INDEX IF NOT EXISTS idx_sdk_agents_status ON sdk_agents(status);
      CREATE INDEX IF NOT EXISTS idx_sdk_agents_client_id ON sdk_agents(client_id);
      CREATE INDEX IF NOT EXISTS idx_sdk_agents_last_activity ON sdk_agents(last_activity);
    `;

    // Create Conversations table
    const conversationsQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_conversations_agent_id ON conversations(agent_id);
      CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);
      CREATE INDEX IF NOT EXISTS idx_conversations_start_time ON conversations(start_time);
      CREATE INDEX IF NOT EXISTS idx_conversations_client_id ON conversations(client_id);
    `;

    // Create LLM Usage table
    const llmUsageQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_llm_usage_timestamp ON llm_usage(timestamp);
      CREATE INDEX IF NOT EXISTS idx_llm_usage_provider_model ON llm_usage(provider, model);
      CREATE INDEX IF NOT EXISTS idx_llm_usage_session_id ON llm_usage(session_id);
      CREATE INDEX IF NOT EXISTS idx_llm_usage_agent_id ON llm_usage(agent_id);
    `;

    // Create Security Events table
    const securityEventsQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
      CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
      CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_security_events_client_id ON security_events(client_id);
    `;

    // Create Compliance Audit table
    const complianceAuditQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_compliance_audit_session_id ON compliance_audit(session_id);
      CREATE INDEX IF NOT EXISTS idx_compliance_audit_timestamp ON compliance_audit(timestamp);
      CREATE INDEX IF NOT EXISTS idx_compliance_audit_hash_chain ON compliance_audit(hash_chain);
      CREATE INDEX IF NOT EXISTS idx_compliance_audit_event_type ON compliance_audit(event_type);
    `;

    // Create Failed Sessions table for better tracking
    const failedSessionsQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_failed_sessions_timestamp ON failed_sessions(timestamp);
      CREATE INDEX IF NOT EXISTS idx_failed_sessions_client_id ON failed_sessions(client_id);
      CREATE INDEX IF NOT EXISTS idx_failed_sessions_failure_reason ON failed_sessions(failure_reason);
    `;

    // Create API Keys table for authentication
    const apiKeysQuery = `
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
      
      CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
      CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys(client_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
    `;

    // Execute all table creation queries using Supabase's rpc function or direct SQL
    const queries = [
      agentsQuery,
      conversationsQuery, 
      llmUsageQuery,
      securityEventsQuery,
      complianceAuditQuery,
      failedSessionsQuery,
      apiKeysQuery
    ];

    for (const query of queries) {
      try {
        // Use Supabase's rpc to execute raw SQL
        const { error } = await supabase.rpc('exec_sql', { sql: query });
        if (error) {
          logger.warn(`Table creation warning: ${error.message}`);
        }
      } catch (error: any) {
        // If rpc doesn't exist, we'll need to create tables manually through Supabase dashboard
        logger.warn(`Could not execute SQL directly: ${error.message}`);
        logger.info('Please create the tables manually in your Supabase dashboard');
      }
    }

    logger.info('✅ AI Agent tracking tables setup complete');
  } catch (error: any) {
    logger.error('❌ Failed to create tables:', error.message);
    throw error;
  }
} 