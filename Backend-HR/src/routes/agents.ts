import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import bcrypt from 'bcryptjs';

const router = Router();

// Validation schemas
const MetricsSchema = z.object({
  agent_id: z.string().uuid(),
  total_tokens: z.number().optional(),
  input_tokens: z.number().optional(),
  output_tokens: z.number().optional(),
  total_cost: z.number().optional(),
  total_requests: z.number().optional(),
  average_latency: z.number().optional(),
  success_rate: z.number().min(0).max(100).optional(),
  timestamp: z.string().optional()
});

const HealthSchema = z.object({
  agent_id: z.string().uuid(),
  status: z.enum(['healthy', 'warning', 'critical']),
  uptime: z.number().optional(),
  response_time: z.number().optional(),
  error_rate: z.number().min(0).max(100).optional(),
  cpu_usage: z.number().min(0).max(100).optional(),
  memory_usage: z.number().min(0).max(100).optional()
});

const ErrorSchema = z.object({
  agent_id: z.string().uuid(),
  error_type: z.string(),
  error_message: z.string(),
  stack_trace: z.string().optional(),
  context: z.any().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional()
});

const SecurityEventSchema = z.object({
  agent_id: z.string().uuid(),
  event_type: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  description: z.string(),
  source_ip: z.string().optional(),
  user_agent: z.string().optional(),
  metadata: z.any().optional()
});

const ComplianceLogSchema = z.object({
  agent_id: z.string().uuid(),
  compliance_type: z.string(),
  status: z.enum(['compliant', 'non_compliant', 'warning']),
  details: z.string(),
  metadata: z.any().optional()
});

// Interface for authenticated requests
interface AuthenticatedRequest extends Request {
  agent?: any;
}

// Middleware to verify agent authentication
const verifyAgent = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authorization header required' });
      return;
    }

    const token = authHeader.substring(7);
    
    // Simple token validation - in production, use proper JWT
    const { data: agent, error } = await supabase
      .from('agents')
      .select('*')
      .eq('api_key_hash', await bcrypt.hash(token, 10))
      .single();

    if (error || !agent) {
      res.status(401).json({ error: 'Invalid agent token' });
      return;
    }

    req.agent = agent;
    next();
  } catch (error) {
    logger.error('Agent verification error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// POST /api/agents/log - Log agent metrics, errors, security events, and compliance
router.post('/log', async (req: Request, res: Response): Promise<void> => {
  try {
    const { type, data } = req.body;

    if (!type || !data) {
      res.status(400).json({ 
        error: 'Missing required fields: type and data' 
      });
      return;
    }

    let result;
    let validatedData;

    switch (type) {
      case 'metrics':
        validatedData = MetricsSchema.parse(data);
        result = await supabase
          .from('agent_metrics')
          .insert({
            ...validatedData,
            timestamp: validatedData.timestamp || new Date().toISOString()
          });
        break;

      case 'error':
        validatedData = ErrorSchema.parse(data);
        result = await supabase
          .from('agent_errors')
          .insert({
            ...validatedData,
            severity: validatedData.severity || 'medium'
          });
        break;

      case 'security':
        validatedData = SecurityEventSchema.parse(data);
        result = await supabase
          .from('agent_security_events')
          .insert({
            ...validatedData,
            severity: validatedData.severity || 'medium'
          });
        break;

      case 'compliance':
        validatedData = ComplianceLogSchema.parse(data);
        result = await supabase
          .from('agent_compliance_logs')
          .insert(validatedData);
        break;

      default:
        res.status(400).json({ 
          error: 'Invalid type. Must be: metrics, error, security, or compliance' 
        });
        return;
    }

    if (result.error) {
      logger.error('Database insert error:', result.error);
      res.status(500).json({ error: 'Failed to log data' });
      return;
    }

    // Update agent last_sync
    await supabase
      .from('agents')
      .update({ last_sync: new Date().toISOString() })
      .eq('id', validatedData.agent_id);

    res.status(201).json({ 
      success: true, 
      message: `${type} logged successfully`,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ 
        error: 'Validation failed', 
        details: error.errors 
      });
      return;
    }
    
    logger.error('Log endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/agents/health - Log agent health status
router.post('/health', async (req: Request, res: Response): Promise<void> => {
  try {
    const validatedData = HealthSchema.parse(req.body);
    
    const { data, error } = await supabase
      .from('agent_health')
      .insert({
        ...validatedData,
        last_ping: new Date().toISOString()
      });

    if (error) {
      logger.error('Health log error:', error);
      res.status(500).json({ error: 'Failed to log health data' });
      return;
    }

    // Update agent last_sync
    await supabase
      .from('agents')
      .update({ 
        last_sync: new Date().toISOString(),
        status: validatedData.status === 'healthy' ? 'active' : 'error'
      })
      .eq('id', validatedData.agent_id);

    res.status(201).json({ 
      success: true, 
      message: 'Health status logged successfully',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ 
        error: 'Validation failed', 
        details: error.errors 
      });
      return;
    }
    
    logger.error('Health endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/agents - Get all agents with aggregated metrics
router.get('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const { organization_id } = req.query;

    let query = supabase
      .from('agents')
      .select(`
        *,
        agent_metrics (
          total_tokens,
          total_cost,
          total_requests,
          average_latency,
          success_rate,
          created_at
        ),
        agent_health (
          status,
          uptime,
          response_time,
          error_rate,
          created_at
        )
      `);

    if (organization_id) {
      query = query.eq('organization_id', organization_id);
    }

    const { data: agents, error } = await query;

    if (error) {
      logger.error('Agents fetch error:', error);
      res.status(500).json({ error: 'Failed to fetch agents' });
      return;
    }

    // Aggregate metrics for each agent
    const agentsWithMetrics = agents?.map((agent: any) => {
      const latestMetrics = agent.agent_metrics?.[0] || {};
      const latestHealth = agent.agent_health?.[0] || {};

      return {
        ...agent,
        metrics: {
          performance: latestHealth.status === 'healthy' ? 
            Math.min(latestMetrics.success_rate || 0, 100) : 
            Math.max((latestMetrics.success_rate || 0) - 20, 0),
          cost: latestMetrics.total_cost || 0,
          requests: latestMetrics.total_requests || 0,
          latency: latestMetrics.average_latency || 0,
          uptime: latestHealth.uptime || 0,
          health_status: latestHealth.status || 'unknown'
        }
      };
    });

    res.json({ 
      agents: agentsWithMetrics || [],
      total: agentsWithMetrics?.length || 0,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Agents list error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/agents/:id/metrics - Get detailed metrics for a specific agent
router.get('/:id/metrics', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    const { timeframe = '24h' } = req.query;

    // Calculate time range
    const now = new Date();
    let startTime;
    
    switch (timeframe) {
      case '1h':
        startTime = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '24h':
        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    const { data: metrics, error: metricsError } = await supabase
      .from('agent_metrics')
      .select('*')
      .eq('agent_id', id)
      .gte('created_at', startTime.toISOString())
      .order('created_at', { ascending: false });

    const { data: health, error: healthError } = await supabase
      .from('agent_health')
      .select('*')
      .eq('agent_id', id)
      .gte('created_at', startTime.toISOString())
      .order('created_at', { ascending: false });

    const { data: errors, error: errorsError } = await supabase
      .from('agent_errors')
      .select('*')
      .eq('agent_id', id)
      .gte('created_at', startTime.toISOString())
      .order('created_at', { ascending: false });

    if (metricsError || healthError || errorsError) {
      logger.error('Metrics fetch error:', { metricsError, healthError, errorsError });
      res.status(500).json({ error: 'Failed to fetch metrics' });
      return;
    }

    res.json({
      agent_id: id,
      timeframe,
      metrics: metrics || [],
      health: health || [],
      errors: errors || [],
      summary: {
        total_requests: metrics?.reduce((sum, m) => sum + (m.total_requests || 0), 0) || 0,
        total_cost: metrics?.reduce((sum, m) => sum + (m.total_cost || 0), 0) || 0,
        average_latency: metrics?.length ? 
          metrics.reduce((sum, m) => sum + (m.average_latency || 0), 0) / metrics.length : 0,
        error_count: errors?.length || 0,
        uptime_average: health?.length ?
          health.reduce((sum, h) => sum + (h.uptime || 0), 0) / health.length : 0
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Agent metrics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export { router as agentRoutes }; 