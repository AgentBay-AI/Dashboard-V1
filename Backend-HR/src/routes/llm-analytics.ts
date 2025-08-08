import { Router, Request, Response, RequestHandler } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';
import { calculateTokenCost, getAvailableProviders, getAvailableModels } from '../config/llm-pricing';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get aggregated LLM usage
const getAggregatedUsage: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { timeframe = '24h' } = req.query;
        let startDate = new Date();
        switch (timeframe) {
            case '1h': startDate.setHours(startDate.getHours() - 1); break;
            case '24h': startDate.setDate(startDate.getDate() - 1); break;
            case '7d': startDate.setDate(startDate.getDate() - 7); break;
            case '30d': startDate.setDate(startDate.getDate() - 30); break;
            default: startDate.setDate(startDate.getDate() - 1);
        }

        const { data: usage, error } = await supabase
            .from('llm_usage')
            .select('*')
            .eq('client_id', authReq.clientId)
            .gte('timestamp', startDate.toISOString());

        if (error) throw error;

        // Build detailed aggregation by provider -> model
        const detailed: Record<string, Record<string, any>> = {};
        let total_input_tokens = 0;
        let total_output_tokens = 0;
        let total_cost = 0;
        let total_requests = 0;

        (usage || []).forEach((r: any) => {
            const provider = (r.provider || 'unknown').toLowerCase();
            const model = (r.model || 'unknown').toLowerCase();
            const input = r.tokens_input || 0;
            const output = r.tokens_output || 0;
            // If cost missing/0, compute via pricing table
            const computedCost = r.cost && Number(r.cost) > 0
              ? Number(r.cost)
              : calculateTokenCost(provider, model, input, output);

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
        });

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
        res.status(500).json({ success: false, error: error.message });
    }
};

// Top models
const getTopModels: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const limit = Number(req.query.limit || 10);
        const sortBy = String(req.query.sort_by || 'cost');

        const { data: usage, error } = await supabase
            .from('llm_usage')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(5000);
        if (error) throw error;

        const byModel: Record<string, { provider: string; model: string; input_tokens: number; output_tokens: number; cost: number; request_count: number; }> = {};
        (usage || []).forEach((r: any) => {
          const key = `${(r.provider||'unknown').toLowerCase()}::${(r.model||'unknown').toLowerCase()}`;
          if (!byModel[key]) byModel[key] = { provider: r.provider, model: r.model, input_tokens: 0, output_tokens: 0, cost: 0, request_count: 0 };
          const input = r.tokens_input || 0;
          const output = r.tokens_output || 0;
          const computedCost = r.cost && Number(r.cost) > 0 ? Number(r.cost) : calculateTokenCost(String(r.provider||'').toLowerCase(), String(r.model||'').toLowerCase(), input, output);
          byModel[key].input_tokens += input;
          byModel[key].output_tokens += output;
          byModel[key].cost += computedCost;
          byModel[key].request_count += 1;
        });

        const models = Object.values(byModel)
          .sort((a, b) => sortBy === 'requests' ? b.request_count - a.request_count : b.cost - a.cost)
          .slice(0, limit);

        res.json({ top_models: models });
    } catch (error: any) {
        logger.error('Error fetching top models:', error);
        res.status(500).json({ success: false, error: error.message });
    }
};

// Pricing info passthrough for UI
const getPricingInfo: RequestHandler = async (_req: Request, res: Response) => {
    try {
        res.json({
          providers: getAvailableProviders().map(p => ({ provider: p, models: getAvailableModels(p) }))
        });
    } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
    }
};

// Mount routes
router.get('/aggregated', requirePermission('read'), getAggregatedUsage);
router.get('/detailed', requirePermission('read'), getAggregatedUsage);
router.get('/top-models', requirePermission('read'), getTopModels);
router.get('/pricing-info', requirePermission('read'), getPricingInfo);

export default router; 