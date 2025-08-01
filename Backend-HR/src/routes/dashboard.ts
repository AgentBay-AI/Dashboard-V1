import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { authenticateApiKey, AuthenticatedRequest, requirePermission } from '../middleware/auth';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// GET /dashboard/overview
router.get('/overview',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      // Get current date for "today" calculations
      const today = new Date();
      const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());

      // Get agent statistics
      const { data: agentData, error: agentError } = await supabase
        .from('sdk_agents')
        .select('status')
        .eq('client_id', req.clientId);

      if (agentError) {
        throw agentError;
      }

      const agentCounts = agentData.reduce((acc, agent) => {
        acc[agent.status] = (acc[agent.status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      // Get conversation statistics for today
      const { data: conversationData, error: conversationError } = await supabase
        .from('conversations')
        .select('status, response_time_ms, quality_score, start_time, security_flags')
        .eq('client_id', req.clientId)
        .gte('start_time', todayStart.toISOString());

      if (conversationError) {
        throw conversationError;
      }

      // Calculate conversation metrics
      const activeConversations = conversationData.filter(c => c.status === 'active').length;
      const totalToday = conversationData.length;
      
      const responseTimes = conversationData
        .filter(c => c.response_time_ms)
        .map(c => c.response_time_ms);
      const avgResponseTime = responseTimes.length > 0 
        ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)
        : 0;

      // Calculate quality score average
      const qualityScores = conversationData
        .filter(c => c.quality_score)
        .map(c => {
          switch (c.quality_score) {
            case 'excellent': return 4;
            case 'good': return 3;
            case 'fair': return 2;
            case 'poor': return 1;
            default: return 0;
          }
        });
      
      const avgQualityScore = qualityScores.length > 0
        ? qualityScores.reduce((a: number, b: number) => a + b, 0) / qualityScores.length
        : 0;
      
      const qualityScoreText = avgQualityScore >= 3.5 ? 'excellent' :
                              avgQualityScore >= 2.5 ? 'good' :
                              avgQualityScore >= 1.5 ? 'fair' : 'poor';

      // Calculate security flags statistics
      const securityFlags = conversationData.reduce((acc, conversation) => {
        const flags = conversation.security_flags || {};
        acc.pii_detected += flags.pii_detected ? 1 : 0;
        acc.tamper_detected += flags.tamper_detected ? 1 : 0;
        acc.compliance_violation += flags.compliance_violation ? 1 : 0;
        return acc;
      }, { pii_detected: 0, tamper_detected: 0, compliance_violation: 0 });

      // Get LLM usage statistics for today
      const { data: llmData, error: llmError } = await supabase
        .from('llm_usage')
        .select('tokens_input, tokens_output, provider, model, metadata')
        .eq('client_id', req.clientId)
        .gte('timestamp', todayStart.toISOString());

      if (llmError) {
        throw llmError;
      }

      const totalTokensToday = llmData.reduce((sum, usage) => sum + usage.tokens_input + usage.tokens_output, 0);
      
      // Get actual cost from metadata
      const costEstimate = llmData.reduce((total, usage) => {
        return total + (usage.metadata?.cost_usd || 0);
      }, 0);

      // Get top models used
      const modelCounts = llmData.reduce((acc, usage) => {
        acc[usage.model] = (acc[usage.model] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const topModels = Object.entries(modelCounts)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 3)
        .map(([model]) => model);

      // Get security events for today
      const { data: securityData, error: securityError } = await supabase
        .from('security_events')
        .select('event_type, severity')
        .eq('client_id', req.clientId)
        .gte('timestamp', todayStart.toISOString());

      if (securityError) {
        throw securityError;
      }

      const securityCounts = securityData.reduce((acc, event) => {
        acc[event.event_type] = (acc[event.event_type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      // Get unclosed sessions count
      const { data: unclosedData, error: unclosedError } = await supabase
        .from('conversations')
        .select('session_id')
        .eq('client_id', req.clientId)
        .eq('status', 'active')
        .lt('start_time', new Date(Date.now() - 60 * 60 * 1000).toISOString()); // Active for more than 1 hour

      if (unclosedError) {
        throw unclosedError;
      }

      const overview = {
        agents: {
          total: agentData.length,
          active: agentCounts.active || 0,
          idle: agentCounts.idle || 0,
          error: agentCounts.error || 0,
          maintenance: agentCounts.maintenance || 0
        },
        conversations: {
          total_today: totalToday,
          active: activeConversations,
          avg_response_time_ms: avgResponseTime,
          avg_quality_score: qualityScoreText
        },
        costs: {
          totalTokens: totalTokensToday,
          monthlyCost: Math.round(costEstimate * 100) / 100,
          costPerAgent: agentData.length ? Math.round((costEstimate / agentData.length) * 100) / 100 : 0
        },
        security: {
          tamper_events: securityCounts.tamper_detected || 0,
          pii_detections: securityCounts.pii_detected || 0,
          unclosed_sessions: unclosedData.length,
          security_flags: {
            pii_detected: securityFlags.pii_detected,
            tamper_detected: securityFlags.tamper_detected,
            compliance_violation: securityFlags.compliance_violation
          }
        },
        last_updated: new Date().toISOString()
      };

      logger.info('Dashboard overview requested', { 
        client_id: req.clientId, 
        total_agents: overview.agents.total,
        conversations_today: overview.conversations.total_today
      });

      res.json(overview);
    } catch (error: any) {
      logger.error('Dashboard overview error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

export { router as dashboardRoutes }; 