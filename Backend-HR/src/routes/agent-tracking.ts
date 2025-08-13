import { Router, Request, Response, RequestHandler } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Active agents endpoint
const getActiveAgents: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { organization_id, agent_id } = req.query as { organization_id?: string; agent_id?: string };

        let baseQuery = supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId);

        // First try only active
        let query = baseQuery.eq('status', 'active');

        if (organization_id) {
            query = query.eq('organization_id', organization_id);
        }
        if (agent_id) {
            query = query.eq('agent_id', agent_id);
        }

        let { data: agents, error } = await query;
        if (error) throw error;

        // Fallback: if no active agents, return all agents for visibility
        if (!agents || agents.length === 0) {
            let allQuery = baseQuery;
            if (organization_id) allQuery = allQuery.eq('organization_id', organization_id);
            if (agent_id) allQuery = allQuery.eq('agent_id', agent_id);
            const resp = await allQuery;
            agents = resp.data || [];
        }

        res.json({ success: true, data: agents || [] });
    } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
    }
};

// Operations overview endpoint
const getOperationsOverview: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { organization_id, agent_id } = req.query as { organization_id?: string; agent_id?: string };

        // Get active agents with optional filters
        let activeQuery = supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId)
            .eq('status', 'active');
        if (organization_id) activeQuery = activeQuery.eq('organization_id', organization_id);
        if (agent_id) activeQuery = activeQuery.eq('agent_id', agent_id);
        const { data: activeAgents, error: agentsError } = await activeQuery;
        if (agentsError) throw agentsError;

        // If none active, fallback to all agents
        let agentsForListing = activeAgents || [];
        if (agentsForListing.length === 0) {
            let allQuery = supabase
                .from('agents')
                .select('*')
                .eq('client_id', authReq.clientId);
            if (organization_id) allQuery = allQuery.eq('organization_id', organization_id);
            if (agent_id) allQuery = allQuery.eq('agent_id', agent_id);
            const { data: allAgents } = await allQuery;
            agentsForListing = allAgents || [];
        }

        // Get recent activity from agent_activity table
        let activityQuery = supabase
            .from('agent_activity')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(10);

        if (organization_id) {
            // filter by agent ids within the organization; derive from all agents in that org
            let idsQuery = supabase
                .from('agents')
                .select('agent_id')
                .eq('client_id', authReq.clientId)
                .eq('organization_id', organization_id);
            const { data: idRows } = await idsQuery;
            const orgAgentIds = (idRows || []).map(r => r.agent_id);
            if (orgAgentIds.length > 0) {
                activityQuery = activityQuery.in('agent_id', orgAgentIds);
            } else {
                activityQuery = activityQuery.eq('agent_id', '___none___');
            }
        }
        if (agent_id) activityQuery = activityQuery.eq('agent_id', agent_id);

        const { data: recentActivity, error: activityError } = await activityQuery;
        if (activityError) throw activityError;

        res.json({ success: true, data: { active_agents: agentsForListing, recent_activity: recentActivity || [] } });
    } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
    }
};

// Mount routes
router.get('/active', requirePermission('read'), getActiveAgents);
router.get('/operations/overview', requirePermission('read'), getOperationsOverview);

export default router; 