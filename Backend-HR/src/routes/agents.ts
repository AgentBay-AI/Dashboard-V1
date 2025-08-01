import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { authenticateApiKey, AuthenticatedRequest, requirePermission } from '../middleware/auth';
import { agentRegisterSchema, agentStatusUpdateSchema, agentActivitySchema } from '../lib/schemas';
import { addTraceContext } from '../middleware/tracing';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// POST /agents/register
router.post('/register', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const data = agentRegisterSchema.parse(req.body);
    
    const { error } = await supabase
      .from('agents')
      .insert({
        ...data,
        ...addTraceContext({}, req)
      });

    if (error) {
      logger.error('Failed to register agent', { error });
      throw error;
    }

    logger.info('Agent registered successfully', { agent_id: data.agent_id });
    res.json({ success: true, data });
  } catch (error: any) {
    logger.error('Failed to register agent', { error });
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /agents/status
router.post('/status', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const data = agentStatusUpdateSchema.parse(req.body);
    
    const { error } = await supabase
      .from('agent_status')
      .insert({
        ...data,
        ...addTraceContext({}, req)
      });

    if (error) {
      logger.error('Failed to update agent status', { error });
      throw error;
    }

    logger.info('Agent status updated', { agent_id: data.agent_id, status: data.status });
    res.json({ success: true, data });
  } catch (error: any) {
    logger.error('Failed to update agent status', { error });
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /agents/activity
router.post('/activity', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const data = agentActivitySchema.parse(req.body);
    
    const { error } = await supabase
      .from('agent_activity')
      .insert({
        ...data,
        ...addTraceContext({}, req)
      });

    if (error) {
      logger.error('Failed to log agent activity', { error });
      throw error;
    }

    logger.info('Agent activity logged', { agent_id: data.agent_id, action: data.action });
    res.json({ success: true, data });
  } catch (error: any) {
    logger.error('Failed to log agent activity', { error });
    res.status(400).json({ success: false, error: error.message });
  }
});

// GET /agents/active
router.get('/active', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('agent_status')
      .select('agent_id, status')
      .eq('status', 'active')
      .order('timestamp', { ascending: false })
      .limit(1000);

    if (error) {
      logger.error('Failed to get active agents', { error });
      throw error;
    }

    // Get unique agents with their latest active status
    const uniqueAgents = (data || []).reduce<Record<string, any>>((acc, curr) => {
      if (!acc[curr.agent_id]) {
        acc[curr.agent_id] = curr;
      }
      return acc;
    }, {});

    res.json({ success: true, data: Object.values(uniqueAgents) });
  } catch (error: any) {
    logger.error('Failed to get active agents', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /agents/{agent_id}/status
router.get('/:agent_id/status', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { agent_id } = req.params;
    
    const { data, error } = await supabase
      .from('agent_status')
      .select('*')
      .eq('agent_id', agent_id)
      .order('timestamp', { ascending: false })
      .limit(1);

    if (error) {
      logger.error('Failed to get agent status', { error });
      throw error;
    }

    res.json({ success: true, data: data[0] || null });
  } catch (error: any) {
    logger.error('Failed to get agent status', { error, agent_id: req.params.agent_id });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /agents/{agent_id}/activity
router.get('/:agent_id/activity', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { agent_id } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;
    
    const { data, error } = await supabase
      .from('agent_activity')
      .select('*')
      .eq('agent_id', agent_id)
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) {
      logger.error('Failed to get agent activity', { error });
      throw error;
    }

    res.json({ success: true, data });
  } catch (error: any) {
    logger.error('Failed to get agent activity', { error, agent_id: req.params.agent_id });
    res.status(500).json({ success: false, error: error.message });
  }
});

interface StatusCount {
  status: string;
  count: string;
}

interface AgentStatus {
  status: string;
}

// GET /operations/overview
router.get('/operations/overview', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    // Get active agents
    const { data: activeAgents, error: activeError } = await supabase
      .from('agent_status')
      .select('agent_id, status')
      .eq('status', 'active')
      .order('timestamp', { ascending: false });

    if (activeError) throw activeError;

    // Get all statuses for distribution
    const { data: statusData, error: statusError } = await supabase
      .from('agent_status')
      .select('status');

    if (statusError) throw statusError;

    // Get recent activity
    const { data: recentActivity, error: activityError } = await supabase
      .from('agent_activity')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(10);

    if (activityError) throw activityError;

    // Calculate status distribution manually
    const statusDistribution = (statusData || []).reduce<Record<string, number>>((acc: Record<string, number>, curr: AgentStatus) => {
      acc[curr.status] = (acc[curr.status] || 0) + 1;
      return acc;
    }, {});

    res.json({
      success: true,
      data: {
        active_agents: activeAgents || [],
        status_distribution: statusDistribution,
        recent_activity: recentActivity || []
      }
    });
  } catch (error: any) {
    logger.error('Failed to get operations overview', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

export { router as agentRoutes }; 