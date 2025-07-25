import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { supabase } from '../lib/supabase';

const router = Router();

// GET /api/analytics/performance - Performance data (empty)
router.get('/performance', async (req: Request, res: Response): Promise<void> => {
  try {
    const { timeframe, agent_id } = req.query;
    // Return empty performance data
    const emptyData = {
      data: [], // No performance data
      average_performance: 0,
      change: '0%',
    };
    res.json(emptyData);
  } catch (error) {
    logger.error('Analytics performance endpoint error:', error);
    res.json({ data: [], average_performance: 0, change: '0%' });
  }
});

// GET /api/analytics/resource-utilization - Resource utilization (empty)
router.get('/resource-utilization', async (req: Request, res: Response): Promise<void> => {
  try {
    // Return empty resource data
    const emptyData = {
      data: {
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 0,
      },
      change: '0%',
    };
    res.json(emptyData);
  } catch (error) {
    logger.error('Analytics resource utilization endpoint error:', error);
    res.json({ data: { cpu_usage: 0, memory_usage: 0, disk_usage: 0 }, change: '0%' });
  }
});

// GET /api/analytics/cost-breakdown - Cost breakdown (empty)
router.get('/cost-breakdown', async (req: Request, res: Response): Promise<void> => {
  try {
    // Return empty cost data
    const emptyData = {
      data: [], // No cost data
      total_cost: 0,
      change: '0%',
    };
    res.json(emptyData);
  } catch (error) {
    logger.error('Analytics cost breakdown endpoint error:', error);
    res.json({ data: [], total_cost: 0, change: '0%' });
  }
});

// GET /api/analytics/activity - Recent activity (empty)
router.get('/activity', async (req: Request, res: Response): Promise<void> => {
  try {
    const { limit = 5 } = req.query;
    // Return empty activity data
    res.json({ data: [] });
  } catch (error) {
    logger.error('Analytics activity endpoint error:', error);
    res.json({ data: [] });
  }
});

export { router as analyticsApiRoutes }; 