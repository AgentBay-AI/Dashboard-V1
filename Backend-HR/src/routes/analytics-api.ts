import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { supabase } from '../lib/supabase';

const router = Router();

// GET /api/analytics/performance - Performance data from database
router.get('/performance', async (req: Request, res: Response): Promise<void> => {
  try {
    const { timeframe, agent_id } = req.query;
    
    // Build query for agent metrics
    let query = supabase
      .from('agent_metrics')
      .select(`
        *,
        agents!inner(id, name, status)
      `)
      .order('created_at', { ascending: false });

    // Filter by agent if specified
    if (agent_id) {
      query = query.eq('agent_id', agent_id);
    }

    // Apply timeframe filter
    if (timeframe) {
      const now = new Date();
      let startDate: Date;
      
      switch (timeframe) {
        case '24h':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case '7d':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case '30d':
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      }
      
      query = query.gte('created_at', startDate.toISOString());
    }

    const { data: metrics, error } = await query.limit(100);

    if (error) {
      logger.error('Error fetching performance metrics:', error);
      res.json({ data: [], average_performance: 0, change: '0%' });
      return;
    }

    // Calculate average performance
    const avgPerformance = metrics.length > 0 
      ? metrics.reduce((sum, m) => sum + (m.success_rate || 0), 0) / metrics.length
      : 0;

    // Format data for charts
    const formattedData = metrics.map(metric => ({
      timestamp: metric.created_at,
      success_rate: metric.success_rate || 0,
      latency: metric.average_latency || 0,
      cost: metric.total_cost || 0,
      requests: metric.total_requests || 0,
      agent_name: metric.agents?.name || 'Unknown'
    }));

    res.json({
      data: formattedData,
      average_performance: Math.round(avgPerformance),
      change: '+0%', // Calculate this based on historical data
      total_requests: metrics.reduce((sum, m) => sum + (m.total_requests || 0), 0),
      total_cost: metrics.reduce((sum, m) => sum + (m.total_cost || 0), 0)
    });

    logger.info(`Performance analytics fetched: ${metrics.length} records`);
  } catch (error) {
    logger.error('Analytics performance endpoint error:', error);
    res.json({ data: [], average_performance: 0, change: '0%' });
  }
});

// GET /api/analytics/resource-utilization - Resource utilization from health data
router.get('/resource-utilization', async (req: Request, res: Response): Promise<void> => {
  try {
    const { data: healthData, error } = await supabase
      .from('agent_health')
      .select(`
        *,
        agents!inner(id, name)
      `)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      logger.error('Error fetching health data:', error);
      res.json({
        data: {
          cpu_usage: 0,
          memory_usage: 0,
          response_time: 0,
          uptime: 0
        }
      });
      return;
    }

    // Calculate averages
    const avgCpu = healthData.length > 0 
      ? healthData.reduce((sum, h) => sum + (h.cpu_usage || 0), 0) / healthData.length
      : 0;

    const avgMemory = healthData.length > 0 
      ? healthData.reduce((sum, h) => sum + (h.memory_usage || 0), 0) / healthData.length
      : 0;

    const avgResponseTime = healthData.length > 0 
      ? healthData.reduce((sum, h) => sum + (h.response_time || 0), 0) / healthData.length
      : 0;

    const avgUptime = healthData.length > 0 
      ? healthData.reduce((sum, h) => sum + (h.uptime || 0), 0) / healthData.length
      : 0;

    res.json({
      data: {
        cpu_usage: Math.round(avgCpu),
        memory_usage: Math.round(avgMemory),
        response_time: Math.round(avgResponseTime),
        uptime: Math.round(avgUptime)
      },
      historical: healthData.map(h => ({
        timestamp: h.created_at,
        cpu_usage: h.cpu_usage || 0,
        memory_usage: h.memory_usage || 0,
        response_time: h.response_time || 0,
        agent_name: h.agents?.name || 'Unknown'
      }))
    });

    logger.info(`Resource utilization analytics fetched: ${healthData.length} records`);
  } catch (error) {
    logger.error('Analytics resource utilization endpoint error:', error);
    res.json({
      data: {
        cpu_usage: 0,
        memory_usage: 0,
        response_time: 0,
        uptime: 0
      }
    });
  }
});

// GET /api/analytics/cost-breakdown - Cost analysis
router.get('/cost-breakdown', async (req: Request, res: Response): Promise<void> => {
  try {
    const { data: metrics, error } = await supabase
      .from('agent_metrics')
      .select(`
        *,
        agents!inner(id, name, provider, model)
      `)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) {
      logger.error('Error fetching cost data:', error);
      res.json({
        total_cost: 0,
        cost_by_provider: [],
        cost_by_model: [],
        daily_costs: []
      });
      return;
    }

    // Calculate total cost
    const totalCost = metrics.reduce((sum, m) => sum + (m.total_cost || 0), 0);

    // Group by provider
    const costByProvider: Record<string, number> = {};
    const costByModel: Record<string, number> = {};

    metrics.forEach(metric => {
      const provider = metric.agents?.provider || 'unknown';
      const model = metric.agents?.model || 'unknown';
      const cost = metric.total_cost || 0;

      costByProvider[provider] = (costByProvider[provider] || 0) + cost;
      costByModel[model] = (costByModel[model] || 0) + cost;
    });

    // Format for charts
    const providerData = Object.entries(costByProvider).map(([provider, cost]) => ({
      provider,
      cost: Math.round(cost * 100) / 100,
      value: Math.round(cost * 100) / 100 // For pie charts
    }));

    const modelData = Object.entries(costByModel).map(([model, cost]) => ({
      model,
      cost: Math.round(cost * 100) / 100
    }));

    res.json({
      total_cost: Math.round(totalCost * 100) / 100,
      cost_by_provider: providerData,
      cost_by_model: modelData,
      daily_costs: [], // Can be calculated from timestamp grouping
      currency: 'USD'
    });

    logger.info(`Cost breakdown analytics fetched: $${totalCost.toFixed(2)} total`);
  } catch (error) {
    logger.error('Analytics cost breakdown endpoint error:', error);
    res.json({
      total_cost: 0,
      cost_by_provider: [],
      cost_by_model: [],
      daily_costs: []
    });
  }
});

// GET /api/analytics/activity - Recent activity data
router.get('/activity', async (req: Request, res: Response): Promise<void> => {
  try {
    const { data: errors, error: errorsError } = await supabase
      .from('agent_errors')
      .select(`
        *,
        agents!inner(id, name)
      `)
      .order('created_at', { ascending: false })
      .limit(20);

    if (errorsError) {
      logger.error('Error fetching activity data:', errorsError);
      res.json({ activities: [] });
      return;
    }

    // Format activities
    const activities = errors.map(error => ({
      id: error.id,
      type: 'error',
      message: `${error.agents?.name || 'Agent'}: ${error.error_message}`,
      timestamp: error.created_at,
      severity: error.severity,
      agent_name: error.agents?.name || 'Unknown',
      details: {
        error_type: error.error_type,
        resolved: error.resolved
      }
    }));

    res.json({
      activities,
      total_count: activities.length
    });

    logger.info(`Activity analytics fetched: ${activities.length} activities`);
  } catch (error) {
    logger.error('Analytics activity endpoint error:', error);
    res.json({ activities: [] });
  }
});

export { router as analyticsApiRoutes }; 