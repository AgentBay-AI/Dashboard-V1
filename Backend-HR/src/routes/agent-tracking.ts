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
        const { data: agents, error } = await supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId)
            .eq('status', 'active');

        if (error) throw error;

        res.json({
            success: true,
            data: agents || []
        });
    } catch (error: any) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Operations overview endpoint
const getOperationsOverview: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        // Get active agents
        const { data: activeAgents, error: agentsError } = await supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId)
            .eq('status', 'active');

        if (agentsError) throw agentsError;

        // Get recent activity from agent_activity table
        const { data: recentActivity, error: activityError } = await supabase
            .from('agent_activity')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(10);

        if (activityError) throw activityError;

        res.json({
            success: true,
            data: {
                active_agents: activeAgents || [],
                recent_activity: recentActivity || []
            }
        });
    } catch (error: any) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Mount routes
router.get('/active', requirePermission('read'), getActiveAgents);
router.get('/operations/overview', requirePermission('read'), getOperationsOverview);

export default router; 