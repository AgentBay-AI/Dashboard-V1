import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import jwt from 'jsonwebtoken';

const router = Router();

// Resolve client identity from either a user JWT or API key (dev supports x-client-id)
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev-only-secret' : undefined as any);
router.use(async (req: any, res, next) => {
  try {
    const raw = Array.isArray(req.headers.authorization) ? req.headers.authorization[0] : req.headers.authorization;
    if (!raw) {
      if (process.env.NODE_ENV !== 'production') {
        const override = (req.headers['x-client-id'] as string | undefined)?.trim();
        if (override) { req.clientId = override; return next(); }
      }
      return res.status(401).json({ error: 'Missing authorization' });
    }
    let token = raw.startsWith('Bearer ') ? raw.slice(7) : raw;
    if (token.startsWith('sk-')) return authenticateApiKey(req, res, next);
    if (!JWT_SECRET) return res.status(401).json({ error: 'Server auth not configured' });
    const decoded: any = jwt.verify(token, JWT_SECRET);
    let cid: string | undefined = decoded?.clientId;
    if (!cid || typeof cid !== 'string' || cid.trim().length === 0) {
      const email: string | undefined = (decoded?.email || decoded?.email_address || (Array.isArray(decoded?.email_addresses) ? decoded.email_addresses[0]?.email_address : undefined));
      if (email) {
        const { data: profile } = await supabase
          .from('profiles')
          .select('client_id')
          .eq('email', email.toLowerCase())
          .maybeSingle();
        cid = profile?.client_id;
      }
    }
    if (!cid) return res.status(401).json({ error: 'Invalid token: clientId missing' });
    (req as AuthenticatedRequest).clientId = cid;
    return next();
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
});

// Helper to apply common agent filters
function applyAgentFilters(
    query: any,
    filters: { organization_id?: string; agent_id?: string }
) {
    const { organization_id, agent_id } = filters;
    let q = query;
    if (organization_id) q = q.eq('organization_id', organization_id);
    if (agent_id) q = q.eq('agent_id', agent_id);
    return q;
}

// Active agents endpoint (now returns all agents ordered by status priority)
const getActiveAgents: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { organization_id, agent_id } = req.query as { organization_id?: string; agent_id?: string };

        const base = () => supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId);

        // Return agents with custom status ordering: active -> idle -> others
        const activeQ = applyAgentFilters(base().eq('status', 'active').order('updated_at', { ascending: false }), { organization_id, agent_id });
        const idleQ = applyAgentFilters(base().eq('status', 'idle').order('updated_at', { ascending: false }), { organization_id, agent_id });
        const otherQ = applyAgentFilters(
            base().neq('status', 'active').neq('status', 'idle').order('updated_at', { ascending: false }),
            { organization_id, agent_id }
        );

        const [activeRes, idleRes, otherRes] = await Promise.all([activeQ, idleQ, otherQ]);
        const allAgents = [
            ...(activeRes.data || []),
            ...(idleRes.data || []),
            ...(otherRes.data || [])
        ];

        const anyError = activeRes.error || idleRes.error || otherRes.error;
        if (anyError) throw anyError;

        res.json({ success: true, data: allAgents });
    } catch (error: any) {
        next(error);
    }
};

// Operations overview endpoint
const getOperationsOverview: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { organization_id, agent_id, limit } = req.query as { organization_id?: string; agent_id?: string; limit?: string };
        const lim = Math.min(Math.max(parseInt(String(limit || '10'), 10) || 10, 1), 50);

        // Build status-ordered agent list: active -> idle -> others (most recent first within each)
        const base = () => supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId);

        const activeQ2 = applyAgentFilters(base().eq('status', 'active').order('updated_at', { ascending: false }), { organization_id, agent_id });
        const idleQ2 = applyAgentFilters(base().eq('status', 'idle').order('updated_at', { ascending: false }), { organization_id, agent_id });
        const otherQ2 = applyAgentFilters(base().neq('status', 'active').neq('status', 'idle').order('updated_at', { ascending: false }), { organization_id, agent_id });

        const [activeRes2, idleRes2, otherRes2] = await Promise.all([activeQ2, idleQ2, otherQ2]);
        const agentsForListing = [
          ...(activeRes2.data || []),
          ...(idleRes2.data || []),
          ...(otherRes2.data || [])
        ];
        const anyAgentErr = activeRes2.error || idleRes2.error || otherRes2.error;
        if (anyAgentErr) throw anyAgentErr;

        // Get recent activity from agent_activity table
        let activityQuery = supabase
            .from('agent_activity')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(lim);

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
        next(error);
    }
};

// Mount routes
router.get('/active', getActiveAgents);
router.get('/operations/overview', getOperationsOverview);

export default router; 
