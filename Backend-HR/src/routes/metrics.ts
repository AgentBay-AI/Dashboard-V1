import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// GET /api/metrics/uptime - heartbeat-based uptime stub (no DB aggregation yet)
const getUptime: RequestHandler = async (req: Request, res: Response, _next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  const { agent_id, window = '24h', instance_id } = req.query as { agent_id?: string; window?: string; instance_id?: string };
  // For now, return a placeholder structure without DB computation
  res.json({
    success: true,
    data: {
      client_id: authReq.clientId,
      agent_id: agent_id || null,
      window,
      agent_uptime_percent: 0,
      last_seen: null,
      restarts: 0,
      missed_heartbeats: 0,
      per_instance: instance_id ? [
        { instance_id, uptime_percent: 0, last_seen: null, restarts: 0, missed_heartbeats: 0 }
      ] : []
    }
  });
};

// Get metrics overview
const getMetricsOverview: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
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
        next(error);
    }
};

// Mount routes
router.get('/uptime', requirePermission('read'), getUptime);
router.get('/overview', requirePermission('read'), getMetricsOverview);

export default router; 
