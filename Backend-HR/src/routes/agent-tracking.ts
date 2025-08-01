import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { authenticateApiKey, AuthenticatedRequest, requirePermission, validateSchema } from '../middleware/auth';
import { addTraceContext, createSpan } from '../middleware/tracing';
import { calculateTokenCost } from '../config/llm-pricing';
import {
  agentRegisterSchema,
  agentStatusSchema,
  conversationStartSchema,
  conversationEndSchema,
  conversationResumeSchema,
  conversationLocalExpiredSchema,
  failedSessionSchema,
  securityMetricsSchema,
  securityTamperSchema,
  llmUsageSchema,
  complianceAuditSchema,
  complianceAcknowledgmentSchema
} from '../lib/schemas';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// 🤖 AGENT OPERATIONS

// POST /agents/register
router.post('/agents/register', 
  requirePermission('write'),
  validateSchema(agentRegisterSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { agent_id, timestamp, client_id, metadata } = req.body;

      // Insert or update agent
      const { data, error } = await supabase
        .from('sdk_agents')
        .upsert({
          agent_id,
          client_id: client_id || req.clientId,
          status: 'active',
          last_activity: timestamp,
          metadata: metadata || {},
          updated_at: new Date().toISOString()
        }, { onConflict: 'agent_id' })
        .select()
        .single();

      if (error) {
        logger.error('Failed to register agent:', error);
        return res.status(500).json({
          error: 'Registration failed',
          message: 'Could not register agent'
        });
      }

      logger.info('Agent registered successfully', { agent_id, client_id: req.clientId });

      res.status(201).json({
        message: 'Agent registered successfully',
        agent: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Agent registration error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /agents/status
router.post('/agents/status',
  requirePermission('write'),
  validateSchema(agentStatusSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { agent_id, status, timestamp, client_id, metadata } = req.body;

      // Update agent status
      const { data, error } = await supabase
        .from('sdk_agents')
        .update({
          status,
          last_activity: timestamp,
          metadata: metadata || {},
          updated_at: new Date().toISOString()
        })
        .eq('agent_id', agent_id)
        .eq('client_id', client_id || req.clientId)
        .select()
        .single();

      if (error || !data) {
        logger.warn('Agent not found for status update', { agent_id, client_id: req.clientId });
        return res.status(404).json({
          error: 'Agent not found',
          message: 'Agent must be registered before updating status'
        });
      }

      logger.info('Agent status updated', { agent_id, status, client_id: req.clientId });

      res.json({
        message: 'Agent status updated successfully',
        agent: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Agent status update error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// GET /agents/overview
router.get('/agents/overview',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      // Get agent counts by status
      const { data: agentCounts, error: countError } = await supabase
        .from('sdk_agents')
        .select('status')
        .eq('client_id', req.clientId);

      if (countError) {
        throw countError;
      }

      const statusCounts = agentCounts.reduce((acc, agent) => {
        acc[agent.status] = (acc[agent.status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const overview = {
        total_agents: agentCounts.length,
        active_agents: statusCounts.active || 0,
        idle_agents: statusCounts.idle || 0,
        error_agents: statusCounts.error || 0,
        maintenance_agents: statusCounts.maintenance || 0,
        last_updated: new Date().toISOString()
      };

      logger.info('Agent overview requested', { client_id: req.clientId, total: overview.total_agents });

      res.json(overview);
    } catch (error: any) {
      logger.error('Agent overview error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// 💬 CONVERSATION OPERATIONS

// POST /conversations/start
router.post('/conversations/start',
  requirePermission('write'),
  validateSchema(conversationStartSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id, agent_id, timestamp, client_id, run_id, user_id, metadata, security_flags } = req.body;

      // Insert conversation with trace context
      const conversationData = addTraceContext({
        session_id,
        agent_id,
        run_id,
        user_id,
        client_id: client_id || req.clientId,
        start_time: timestamp,
        last_activity: timestamp,
        status: 'active',
        metadata: metadata || {},
        security_flags: security_flags || {}
      }, req);

      const { data, error } = await supabase
        .from('conversations')
        .insert(conversationData)
        .select()
        .single();

      if (error) {
        if (error.code === '23505') { // Unique constraint violation
          return res.status(409).json({
            error: 'Conversation already exists',
            message: 'A conversation with this session_id already exists'
          });
        }
        logger.error('Failed to start conversation:', error);
        return res.status(500).json({
          error: 'Conversation start failed',
          message: 'Could not start conversation'
        });
      }

      logger.info('Conversation started', { session_id, agent_id, client_id: req.clientId });

      res.status(201).json({
        message: 'Conversation started successfully',
        conversation: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Conversation start error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /conversations/end
router.post('/conversations/end',
  requirePermission('write'),
  validateSchema(conversationEndSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id, timestamp, client_id, outcome, quality_score, response_time_ms, user_satisfaction, metadata, security_flags } = req.body;

      // Update conversation with trace context
      const updateData = addTraceContext({
        end_time: timestamp,
        last_activity: timestamp,
        status: 'ended',
        outcome,
        quality_score,
        response_time_ms,
        user_satisfaction,
        metadata: metadata || {},
        security_flags: security_flags || {}
      }, req);

      const { data, error } = await supabase
        .from('conversations')
        .update(updateData)
        .eq('session_id', session_id)
        .eq('client_id', client_id || req.clientId)
        .select()
        .single();

      if (error || !data) {
        logger.warn('Conversation not found for end', { session_id, client_id: req.clientId });
        return res.status(404).json({
          error: 'Conversation not found',
          message: 'Conversation must be started before ending'
        });
      }

      logger.info('Conversation ended', { session_id, outcome, client_id: req.clientId });

      res.json({
        message: 'Conversation ended successfully',
        conversation: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Conversation end error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /conversations/resume
router.post('/conversations/resume',
  requirePermission('write'),
  validateSchema(conversationResumeSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id, agent_id, timestamp, client_id, resume_reason } = req.body;

      // Update conversation
      const { data, error } = await supabase
        .from('conversations')
        .update({
          last_activity: timestamp,
          status: 'active',
          metadata: {
            resume_reason,
            resumed_at: timestamp
          }
        })
        .eq('session_id', session_id)
        .eq('client_id', client_id || req.clientId)
        .select()
        .single();

      if (error || !data) {
        logger.warn('Conversation not found for resume', { session_id, client_id: req.clientId });
        return res.status(404).json({
          error: 'Conversation not found',
          message: 'Cannot resume conversation that does not exist'
        });
      }

      logger.info('Conversation resumed', { session_id, resume_reason, client_id: req.clientId });

      res.json({
        message: 'Conversation resumed successfully',
        conversation: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Conversation resume error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /conversations/local-expired
router.post('/conversations/local-expired',
  requirePermission('write'),
  validateSchema(conversationLocalExpiredSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { expired_sessions, timestamp, client_id } = req.body;

      const sessionIds = expired_sessions.map((s: any) => s.session_id);
      
      // Update all expired sessions
      const { data, error } = await supabase
        .from('conversations')
        .update({
          status: 'expired',
          last_activity: timestamp,
          metadata: {
            expired_at: timestamp,
            expiry_batch: true
          }
        })
        .in('session_id', sessionIds)
        .eq('client_id', client_id || req.clientId)
        .select();

      if (error) {
        logger.error('Failed to update expired sessions:', error);
        return res.status(500).json({
          error: 'Update failed',
          message: 'Could not update expired sessions'
        });
      }

      logger.info('Expired sessions updated', { 
        count: expired_sessions.length, 
        client_id: req.clientId 
      });

      res.json({
        message: 'Expired sessions updated successfully',
        updated_sessions: data?.length || 0,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Local expired error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// GET /conversations/:session_id
router.get('/conversations/:session_id',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id } = req.params;

      const { data, error } = await supabase
        .from('conversations')
        .select('*')
        .eq('session_id', session_id)
        .eq('client_id', req.clientId)
        .single();

      if (error || !data) {
        return res.status(404).json({
          error: 'Conversation not found',
          message: 'No conversation found with the specified session_id'
        });
      }

      res.json(data);
    } catch (error: any) {
      logger.error('Get conversation error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /conversations/failed-session
router.post('/conversations/failed-session',
  requirePermission('write'),
  validateSchema(failedSessionSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id, agent_id, timestamp, client_id, failure_reason, error_details } = req.body;

      // Insert failed session record
      const { data, error } = await supabase
        .from('failed_sessions')
        .insert({
          session_id,
          agent_id,
          timestamp,
          client_id: client_id || req.clientId,
          failure_reason,
          error_details: error_details || {}
        })
        .select()
        .single();

      if (error) {
        logger.error('Failed to record failed session:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record failed session'
        });
      }

      // Also try to update conversation status if it exists
      await supabase
        .from('conversations')
        .update({
          status: 'failed',
          last_activity: timestamp,
          metadata: {
            failure_reason,
            error_details,
            failed_at: timestamp
          }
        })
        .eq('session_id', session_id)
        .eq('client_id', client_id || req.clientId);

      logger.warn('Failed session recorded', { session_id, failure_reason, client_id: req.clientId });

      res.status(201).json({
        message: 'Failed session recorded successfully',
        failed_session: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Failed session error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// 🔐 SECURITY ENDPOINTS

// POST /security/metrics
router.post('/security/metrics',
  requirePermission('write'),
  validateSchema(securityMetricsSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { event_type, timestamp, agent_id, client_id, unclosed_count, unclosed_sessions, metadata } = req.body;

      // Determine severity based on unclosed sessions count
      let severity = 'low';
      if (unclosed_count && unclosed_count > 10) severity = 'high';
      else if (unclosed_count && unclosed_count > 5) severity = 'medium';

      // Insert security event with trace context
      const securityEventData = addTraceContext({
        event_type,
        timestamp,
        agent_id,
        client_id: client_id || req.clientId,
        severity,
        event_data: {
          unclosed_count,
          unclosed_sessions: unclosed_sessions || [],
          metadata: metadata || {}
        }
      }, req);

      const { data, error } = await supabase
        .from('security_events')
        .insert(securityEventData)
        .select()
        .single();

      if (error) {
        logger.error('Failed to record security metrics:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record security metrics'
        });
      }

      logger.warn('Security metrics recorded', { 
        event_type, 
        unclosed_count, 
        client_id: req.clientId 
      });

      res.status(201).json({
        message: 'Security metrics recorded successfully',
        event: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Security metrics error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /security/tamper
router.post('/security/tamper',
  requirePermission('write'),
  validateSchema(securityTamperSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { event_type, timestamp, agent_id, client_id, sdk_version, checksum_expected, checksum_actual, modified_files, severity } = req.body;

      // Insert tamper detection event with trace context
      const tamperEventData = addTraceContext({
        event_type,
        timestamp,
        agent_id,
        client_id: client_id || req.clientId,
        severity,
        event_data: {
          sdk_version,
          checksum_expected,
          checksum_actual,
          modified_files
        }
      }, req);

      const { data, error } = await supabase
        .from('security_events')
        .insert(tamperEventData)
        .select()
        .single();

      if (error) {
        logger.error('Failed to record tamper detection:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record tamper detection'
        });
      }

      logger.error('SECURITY ALERT: Tamper detected', { 
        agent_id, 
        modified_files, 
        severity, 
        client_id: req.clientId 
      });

      res.status(201).json({
        message: 'Tamper detection recorded successfully',
        event: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Tamper detection error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// 📊 LLM USAGE ENDPOINT

// POST /llm-usage
router.post('/llm-usage',
  requirePermission('write'),
  validateSchema(llmUsageSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { timestamp, agent_id, provider, model, tokens_input, tokens_output, session_id, client_id, metadata } = req.body;

      // Calculate cost based on pricing
      const cost = calculateTokenCost(provider, model, tokens_input, tokens_output);

      // Insert LLM usage record with trace context
      const llmUsageData = addTraceContext({
        timestamp,
        agent_id,
        provider,
        model,
        tokens_input,
        tokens_output,
        session_id,
        client_id: client_id || req.clientId,
        metadata: { ...metadata, cost_usd: cost }
      }, req);

      const { data, error } = await supabase
        .from('llm_usage')
        .insert(llmUsageData)
        .select()
        .single();

      if (error) {
        logger.error('Failed to record LLM usage:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record LLM usage'
        });
      }

      logger.info('LLM usage recorded', { 
        provider, 
        model, 
        tokens_input,
        tokens_output,
        cost_usd: cost,
        session_id, 
        client_id: req.clientId 
      });

      res.status(201).json({
        message: 'LLM usage recorded successfully',
        usage: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('LLM usage error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// 📋 COMPLIANCE ENDPOINTS

// POST /compliance/audit
router.post('/compliance/audit',
  requirePermission('write'),
  validateSchema(complianceAuditSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { audit_entry, hash_chain, current_hash, client_id } = req.body;

      // Insert compliance audit record
      const { data, error } = await supabase
        .from('compliance_audit')
        .insert({
          session_id: audit_entry.session_id,
          timestamp: audit_entry.timestamp,
          event_type: audit_entry.event_type,
          compliance_flags: audit_entry.compliance_flags || {},
          policy_violations: audit_entry.policy_violations || [],
          hash_chain,
          current_hash,
          client_id: client_id || req.clientId
        })
        .select()
        .single();

      if (error) {
        logger.error('Failed to record compliance audit:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record compliance audit'
        });
      }

      logger.info('Compliance audit recorded', { 
        session_id: audit_entry.session_id, 
        event_type: audit_entry.event_type,
        client_id: req.clientId 
      });

      res.status(201).json({
        message: 'Compliance audit recorded successfully',
        audit: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Compliance audit error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// POST /compliance/acknowledgment
router.post('/compliance/acknowledgment',
  requirePermission('write'),
  validateSchema(complianceAcknowledgmentSchema),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { session_id, policy_type, acknowledged_by, acknowledgment_reason, timestamp, client_id } = req.body;

      // Insert acknowledgment record
      const { data, error } = await supabase
        .from('compliance_audit')
        .insert({
          session_id,
          timestamp,
          event_type: 'policy_acknowledgment',
          compliance_flags: {
            policy_type,
            acknowledged_by,
            acknowledgment_reason
          },
          policy_violations: [],
          current_hash: 'acknowledgment_' + Date.now(),
          client_id: client_id || req.clientId
        })
        .select()
        .single();

      if (error) {
        logger.error('Failed to record compliance acknowledgment:', error);
        return res.status(500).json({
          error: 'Recording failed',
          message: 'Could not record compliance acknowledgment'
        });
      }

      logger.info('Compliance acknowledgment recorded', { 
        session_id, 
        policy_type, 
        acknowledged_by,
        client_id: req.clientId 
      });

      res.status(201).json({
        message: 'Compliance acknowledgment recorded successfully',
        acknowledgment: data,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Compliance acknowledgment error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

export { router as agentTrackingRoutes }; 