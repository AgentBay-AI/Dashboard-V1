import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, AuthenticatedRequest } from '../middleware/auth';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';
import { calculateTokenCost, getAvailableProviders, getAvailableModels } from '../config/llm-pricing';

const router = Router();

// Resolve client identity from JWT or API key
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

// Helper function to filter by organization
const applyOrganizationFilter = async (query: any, authReq: AuthenticatedRequest, organization_id: string) => {
    const { data: orgAgents } = await supabase
        .from('agents')
        .select('agent_id')
        .eq('client_id', authReq.clientId)
        .eq('organization_id', organization_id);
    const ids = (orgAgents || []).map(a => a.agent_id);
    return ids.length > 0 ? query.in('agent_id', ids) : query.eq('agent_id', null);
};

// Validate query parameters
const validateTimeframe = (timeframe: string): string => {
    const validTimeframes = ['1h', '24h', '7d', '30d'];
    return validTimeframes.includes(timeframe) ? timeframe : '24h';
};

// Get aggregated LLM usage
const getAggregatedUsage: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const timeframe = validateTimeframe(String(req.query.timeframe || '24h'));
        const organization_id = req.query.organization_id ? String(req.query.organization_id) : undefined;
        const agent_id = req.query.agent_id ? String(req.query.agent_id) : undefined;
        
        let startDate = new Date();
        switch (timeframe) {
            case '1h': startDate.setHours(startDate.getHours() - 1); break;
            case '24h': startDate.setDate(startDate.getDate() - 1); break;
            case '7d': startDate.setDate(startDate.getDate() - 7); break;
            case '30d': startDate.setDate(startDate.getDate() - 30); break;
        }

        let query = supabase
            .from('llm_usage')
            .select('*')
            .gte('timestamp', startDate.toISOString())
            .eq('client_id', authReq.clientId);
        
        if (agent_id) query = query.eq('agent_id', agent_id);
        if (organization_id) {
            query = await applyOrganizationFilter(query, authReq, organization_id);
        }

        const { data: usage, error } = await query;

        if (error) throw error;

        // Build detailed aggregation by provider -> model
        const detailed: Record<string, Record<string, any>> = {};
        let total_input_tokens = 0;
        let total_output_tokens = 0;
        let total_cost = 0;
        let total_requests = 0;

        for (const r of usage || []) {
            const provider = r.provider ? String(r.provider).toLowerCase() : 'unknown';
            const model = r.model ? String(r.model).toLowerCase() : 'unknown';
            const input = Number(r.tokens_input) || 0;
            const output = Number(r.tokens_output) || 0;

            let computedCost = 0;
            if (r.cost && Number(r.cost) > 0) {
                computedCost = Number(r.cost);
            } else if (provider && model && provider !== 'unknown' && model !== 'unknown') {
                const calculatedCost = await calculateTokenCost(provider, model, input, output);
                computedCost = typeof calculatedCost === 'number' && !isNaN(calculatedCost) ? calculatedCost : 0;
            }

            detailed[provider] = detailed[provider] || {};
            detailed[provider][model] = detailed[provider][model] || {
              input_tokens: 0, output_tokens: 0, cost: 0, request_count: 0
            };

            detailed[provider][model].input_tokens += input;
            detailed[provider][model].output_tokens += output;
            detailed[provider][model].cost += computedCost;
            detailed[provider][model].request_count += 1;

            total_input_tokens += input;
            total_output_tokens += output;
            total_cost += computedCost;
            total_requests += 1;
        }

        res.json({
            timeframe: {
                start: startDate.toISOString(),
                end: new Date().toISOString(),
                requested_timeframe: String(timeframe)
            },
            summary: {
                total_cost: Number(total_cost.toFixed(6)),
                total_input_tokens,
                total_output_tokens,
                total_requests,
                providers_used: Object.keys(detailed).length
            },
            detailed
        });

    } catch (error: any) {
        logger.error('Error fetching LLM usage:', error);
        next(error);
    }
};

// Get detailed LLM usage with individual records
const getDetailedUsage: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const timeframe = validateTimeframe(String(req.query.timeframe || '24h'));
        const organization_id = req.query.organization_id ? String(req.query.organization_id) : undefined;
        const agent_id = req.query.agent_id ? String(req.query.agent_id) : undefined;
        const limit = Math.min(Number(req.query.limit) || 1000, 10000);
        
        let startDate = new Date();
        switch (timeframe) {
            case '1h': startDate.setHours(startDate.getHours() - 1); break;
            case '24h': startDate.setDate(startDate.getDate() - 1); break;
            case '7d': startDate.setDate(startDate.getDate() - 7); break;
            case '30d': startDate.setDate(startDate.getDate() - 30); break;
        }

        let query = supabase
            .from('llm_usage')
            .select('*')
            .gte('timestamp', startDate.toISOString())
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(limit);
            
        if (agent_id) query = query.eq('agent_id', agent_id);
        if (organization_id) {
            query = await applyOrganizationFilter(query, authReq, organization_id);
        }

        const { data: usage, error } = await query;
        if (error) throw error;

        const detailedUsage = (usage || []).map((r: any) => ({
            timestamp: r.timestamp,
            agent_id: r.agent_id,
            provider: r.provider || 'unknown',
            model: r.model || 'unknown',
            input_tokens: Number(r.tokens_input) || 0,
            output_tokens: Number(r.tokens_output) || 0,
            cost: Number(r.cost) || 0
        }));

        res.json({
            timeframe: {
                start: startDate.toISOString(),
                end: new Date().toISOString(),
                requested_timeframe: timeframe
            },
            total_records: detailedUsage.length,
            usage: detailedUsage
        });

    } catch (error: any) {
        logger.error('Error fetching detailed LLM usage:', error);
        next(error);
    }
};

// Top models
const getTopModels: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const limit = Math.min(Number(req.query.limit) || 10, 100);
        const sortBy = ['cost', 'requests'].includes(String(req.query.sort_by)) ? String(req.query.sort_by) : 'cost';
        const timeframe = validateTimeframe(String(req.query.timeframe || '7d'));
        const organization_id = req.query.organization_id ? String(req.query.organization_id) : undefined;
        const agent_id = req.query.agent_id ? String(req.query.agent_id) : undefined;

        let startDate = new Date();
        switch (timeframe) {
            case '1h': startDate.setHours(startDate.getHours() - 1); break;
            case '24h': startDate.setDate(startDate.getDate() - 1); break;
            case '7d': startDate.setDate(startDate.getDate() - 7); break;
            case '30d': startDate.setDate(startDate.getDate() - 30); break;
        }

        let query = supabase
            .from('llm_usage')
            .select('*')
            .gte('timestamp', startDate.toISOString())
            .eq('client_id', authReq.clientId);
            
        if (agent_id) query = query.eq('agent_id', agent_id);
        if (organization_id) {
            query = await applyOrganizationFilter(query, authReq, organization_id);
        }

        const { data: usage, error } = await query;
        if (error) throw error;

        const byModel: Record<string, { provider: string; model: string; input_tokens: number; output_tokens: number; cost: number; request_count: number; }> = {};
        for (const r of usage || []) {
            const provider = r.provider ? String(r.provider).toLowerCase() : 'unknown';
            const model = r.model ? String(r.model).toLowerCase() : 'unknown';
            const key = `${provider}::${model}`;
            
            if (!byModel[key]) {
                byModel[key] = { 
                    provider: r.provider || 'unknown', 
                    model: r.model || 'unknown', 
                    input_tokens: 0, 
                    output_tokens: 0, 
                    cost: 0, 
                    request_count: 0 
                };
            }
            
            const input = Number(r.tokens_input) || 0;
            const output = Number(r.tokens_output) || 0;
            
            let computedCost = 0;
            if (r.cost && Number(r.cost) > 0) {
                computedCost = Number(r.cost);
            } else if (provider && model && provider !== 'unknown' && model !== 'unknown') {
                const calculatedCost = await calculateTokenCost(provider, model, input, output);
                computedCost = typeof calculatedCost === 'number' && !isNaN(calculatedCost) ? calculatedCost : 0;
            }
            
            byModel[key].input_tokens += input;
            byModel[key].output_tokens += output;
            byModel[key].cost += computedCost;
            byModel[key].request_count += 1;
        }

        const models = Object.values(byModel)
          .sort((a, b) => sortBy === 'requests' ? b.request_count - a.request_count : b.cost - a.cost)
          .slice(0, limit);

        res.json({ top_models: models });
    } catch (error: any) {
        logger.error('Error fetching top models:', error);
        next(error);
    }
};

// Pricing info passthrough for UI
const getPricingInfo: RequestHandler = async (_req: Request, res: Response, next: NextFunction) => {
    try {
        res.json({
          providers: getAvailableProviders().map(p => ({ provider: p, models: getAvailableModels(p) }))
        });
    } catch (error: any) {
        next(error);
    }
};

// Mount routes
router.get('/aggregated', getAggregatedUsage);
router.get('/detailed', getDetailedUsage);
router.get('/top-models', getTopModels);
router.get('/pricing-info', getPricingInfo);

export default router; 
