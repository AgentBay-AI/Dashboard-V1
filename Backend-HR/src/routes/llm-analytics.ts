import { Router, Request, Response, RequestHandler } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get aggregated LLM usage
const getAggregatedUsage: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { timeframe = '24h' } = req.query;
        
        // Calculate date range based on timeframe
        let startDate = new Date();
        switch (timeframe) {
            case '1h':
                startDate.setHours(startDate.getHours() - 1);
                break;
            case '24h':
                startDate.setDate(startDate.getDate() - 1);
                break;
            case '7d':
                startDate.setDate(startDate.getDate() - 7);
                break;
            case '30d':
                startDate.setDate(startDate.getDate() - 30);
                break;
            default:
                startDate.setDate(startDate.getDate() - 1);
        }

        const { data: usage, error } = await supabase
            .from('llm_usage')
            .select('*')
            .eq('client_id', authReq.clientId)
            .gte('timestamp', startDate.toISOString());

        if (error) throw error;

        // Calculate summary statistics
        const summary = (usage || []).reduce((acc, record) => {
            acc.total_input_tokens += record.tokens_input || 0;
            acc.total_output_tokens += record.tokens_output || 0;
            acc.total_cost += record.cost || 0;
            acc.total_requests += 1;
            return acc;
        }, {
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost: 0,
            total_requests: 0
        });

        res.json({
            success: true,
            data: {
                timeframe,
                summary,
                details: usage || []
            }
        });

    } catch (error: any) {
        logger.error('Error fetching LLM usage:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Get detailed usage breakdown
const getDetailedUsage: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { data: usage, error } = await supabase
            .from('llm_usage')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('timestamp', { ascending: false })
            .limit(100);

        if (error) throw error;

        res.json({
            success: true,
            data: usage || []
        });

    } catch (error: any) {
        logger.error('Error fetching detailed LLM usage:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Mount routes
router.get('/aggregated', requirePermission('read'), getAggregatedUsage);
router.get('/detailed', requirePermission('read'), getDetailedUsage);

export default router; 