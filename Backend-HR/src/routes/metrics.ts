import { Router, Request, Response, RequestHandler } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get metrics overview
const getMetricsOverview: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { data: metrics, error } = await supabase
            .from('view_success_rate')
            .select('*')
            .eq('client_id', authReq.clientId);

        if (error) {
            logger.error('Metrics fetch error:', error);
            throw error;
        }

        res.json(metrics || []);
    } catch (error: any) {
        logger.error('Error fetching metrics:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Mount routes
router.get('/overview', requirePermission('read'), getMetricsOverview);

export default router; 