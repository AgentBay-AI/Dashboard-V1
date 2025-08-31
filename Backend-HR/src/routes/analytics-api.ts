import { Router, Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';

const router = Router();

// Apply authentication and require read permission
router.use(authenticateApiKey);

function toBucket(ts: string, useDaily: boolean): string {
  const d = new Date(ts);
  if (useDaily) {
    d.setHours(0, 0, 0, 0);
  } else {
    d.setMinutes(0, 0, 0);
  }
  return d.toISOString();
}

// GET /api/dashboard/performance - Performance data from database
router.get('/performance', requirePermission('read'), async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { timeframe = '24h', agent_id, organization_id } = req.query as { timeframe?: string; agent_id?: string; organization_id?: string };

    // Choose hourly view up to 24h, daily beyond
    const hours = parseInt(String(timeframe), 10) || 24;
    const useDaily = hours > 24;
    const view = useDaily ? 'view_agent_metrics_daily' : 'view_agent_metrics_hourly';

    const startDate = new Date();
    startDate.setHours(startDate.getHours() - hours);

    // Build query using view
    let query = supabase
      .from(view)
      .select('*')
      .eq('client_id', authReq.clientId)
      .gte('bucket', startDate.toISOString())
      .order('bucket', { ascending: true });

    if (agent_id) query = query.eq('agent_id', agent_id);

    if (organization_id) {
      // Filter by agents in org
      const { data: orgAgents } = await supabase
        .from('agents')
        .select('agent_id')
        .eq('client_id', authReq.clientId)
        .eq('organization_id', organization_id);
      const ids = (orgAgents || []).map(a => a.agent_id);
      if (ids.length > 0) query = query.in('agent_id', ids); else query = query.eq('agent_id', '___none___');
    }

    let { data: points, error } = await query;

    // Fallback if view missing: aggregate from agent_metrics
    if (error && (error as any).code === '42P01') {
      logger.warn('Aggregated views missing, falling back to raw agent_metrics aggregation');
      let raw = supabase
        .from('agent_metrics')
        .select('*')
        .eq('client_id', authReq.clientId)
        .gte('created_at', startDate.toISOString())
        .order('created_at', { ascending: true });
      if (agent_id) raw = raw.eq('agent_id', agent_id);
      if (organization_id) {
        const { data: orgAgents } = await supabase
          .from('agents')
          .select('agent_id')
          .eq('client_id', authReq.clientId)
          .eq('organization_id', organization_id);
        const ids = (orgAgents || []).map(a => a.agent_id);
        if (ids.length > 0) raw = raw.in('agent_id', ids); else raw = raw.eq('agent_id', '___none___');
      }
      const { data: metrics, error: err2 } = await raw;
      if (err2) {
        logger.error('Raw aggregation fetch failed:', err2);
        res.json({ data: [] });
        return;
      }
      const buckets: Record<string, { srSum: number; srCount: number; latSum: number; latCount: number; req: number; cost: number; } > = {};
      (metrics || []).forEach((m: any) => {
        const b = toBucket(m.created_at, useDaily);
        if (!buckets[b]) buckets[b] = { srSum: 0, srCount: 0, latSum: 0, latCount: 0, req: 0, cost: 0 };
        if (typeof m.success_rate === 'number') { buckets[b].srSum += m.success_rate; buckets[b].srCount += 1; }
        if (typeof m.average_latency === 'number') { buckets[b].latSum += m.average_latency; buckets[b].latCount += 1; }
        buckets[b].req += Number(m.total_requests || 0);
        buckets[b].cost += Number(m.total_cost || 0);
      });
      const formatted = Object.keys(buckets)
        .sort()
        .map(b => ({
          timestamp: b,
          success_rate: buckets[b].srCount ? Math.round(buckets[b].srSum / buckets[b].srCount) : 0,
          latency: buckets[b].latCount ? Math.round(buckets[b].latSum / buckets[b].latCount) : 0,
          requests: buckets[b].req,
          cost: Number(buckets[b].cost.toFixed(6))
        }));
      res.json({ data: formatted });
      return;
    }

    if (error) {
      logger.error('Error fetching aggregated performance:', error);
      res.json({ data: [] });
      return;
    }

    const formattedData = (points || []).map((p: any) => ({
      timestamp: p.bucket,
      success_rate: p.success_rate || 0,
      latency: p.average_latency || 0,
      cost: p.total_cost || 0,
      requests: p.total_requests || 0,
    }));

    res.json({ data: formattedData });
  } catch (error) {
    logger.error('Analytics performance endpoint error:', error);
    next(error as any);
  }
});

// GET /api/dashboard/resource-utilization - Resource utilization from health data
router.get('/resource-utilization', requirePermission('read'), async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { agent_id, organization_id } = req.query as { agent_id?: string; organization_id?: string };

    let query = supabase
      .from('agent_health')
      .select(`
        *,
        agents!inner(agent_id, name, organization_id)
      `)
      .eq('client_id', authReq.clientId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (agent_id) query = query.eq('agent_id', agent_id);
    if (organization_id) query = query.eq('agents.organization_id', organization_id);

    const { data: healthData, error } = await query;

    if (error) {
      logger.error('Error fetching health data:', error);
      res.json({ data: { cpu_usage: 0, memory_usage: 0, response_time: 0, uptime: 0 } });
      return;
    }

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
    next(error as any);
  }
});

// GET /api/dashboard/cost-breakdown - Cost analysis
router.get('/cost-breakdown', requirePermission('read'), async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { agent_id, organization_id, days: daysParam } = req.query as { agent_id?: string; organization_id?: string; days?: string };

    // Parse lookback window and compute time bounds
    let days = parseInt(String(daysParam ?? '30'), 10);
    if (isNaN(days) || days <= 0) days = 30;
    if (days > 90) days = 90; // basic guardrail
    const now = new Date();
    const startDate = new Date(now);
    startDate.setDate(startDate.getDate() - days);

    // Prefer aggregated daily view for larger windows, fallback if not present
    const useDailyView = days > 30;
    if (useDailyView) {
      let vq = supabase
        .from('view_costs_daily')
        .select('*')
        .eq('client_id', authReq.clientId)
        .gte('bucket', startDate.toISOString())
        .lte('bucket', now.toISOString())
        .order('bucket', { ascending: true });

      if (agent_id) vq = vq.eq('agent_id', agent_id);
      if (organization_id) vq = vq.eq('organization_id', organization_id);

      const { data: viewRows, error: viewErr } = await vq as any;

      if (!viewErr && viewRows) {
        // Totals
        const totalCost = viewRows.reduce((sum: number, r: any) => sum + Number(r.total_cost || 0), 0);

        // Breakdowns
        const costByProvider: Record<string, number> = {};
        const costByModel: Record<string, number> = {};
        viewRows.forEach((r: any) => {
          const provider = r.provider || 'unknown';
          const model = r.model || 'unknown';
          const cost = Number(r.total_cost || 0);
          costByProvider[provider] = (costByProvider[provider] || 0) + cost;
          costByModel[model] = (costByModel[model] || 0) + cost;
        });
        const providerData = Object.entries(costByProvider).map(([provider, cost]) => ({
          provider,
          cost: Math.round(cost * 100) / 100,
          value: Math.round(cost * 100) / 100
        }));
        const modelData = Object.entries(costByModel).map(([model, cost]) => ({ model, cost: Math.round(cost * 100) / 100 }));

        // Daily series from view rows with zero-fill
        const buckets: Record<string, number> = {};
        (viewRows || []).forEach((r: any) => {
          const key = toBucket(r.bucket, true);
          buckets[key] = (buckets[key] || 0) + Number(r.total_cost || 0);
        });
        const series: Array<{ timestamp: string; cost: number }> = [];
        const cur = new Date(startDate);
        cur.setHours(0, 0, 0, 0);
        const end = new Date(now);
        end.setHours(0, 0, 0, 0);
        while (cur <= end) {
          const key = toBucket(cur.toISOString(), true);
          const val = buckets[key] || 0;
          series.push({ timestamp: key, cost: Math.round(val * 100) / 100 });
          cur.setDate(cur.getDate() + 1);
        }

        res.json({
          total_cost: Math.round(totalCost * 100) / 100,
          cost_by_provider: providerData,
          cost_by_model: modelData,
          daily_costs: series,
          currency: 'USD'
        });
        return;
      }
      if (viewErr && (viewErr as any).code !== '42P01') {
        logger.warn('view_costs_daily query failed, falling back to raw metrics:', viewErr);
      }
      // else: missing view (42P01) -> fall through to raw metrics
    }

    let query = supabase
      .from('agent_metrics')
      .select(`
        *,
        agents!inner(agent_id, name, provider, model, organization_id)
      `)
      .eq('client_id', authReq.clientId)
      .gte('created_at', startDate.toISOString())
      .lte('created_at', now.toISOString())
      .order('created_at', { ascending: false });

    if (agent_id) query = query.eq('agent_id', agent_id);
    if (organization_id) query = query.eq('agents.organization_id', organization_id);

    const { data: metrics, error } = await query;

    if (error) {
      logger.error('Error fetching cost data:', error);
      res.json({ total_cost: 0, cost_by_provider: [], cost_by_model: [], daily_costs: [] });
      return;
    }

    const totalCost = metrics.reduce((sum, m) => sum + (m.total_cost || 0), 0);

    const costByProvider: Record<string, number> = {};
    const costByModel: Record<string, number> = {};

    metrics.forEach(metric => {
      const provider = metric.agents?.provider || 'unknown';
      const model = metric.agents?.model || 'unknown';
      const cost = metric.total_cost || 0;
      costByProvider[provider] = (costByProvider[provider] || 0) + cost;
      costByModel[model] = (costByModel[model] || 0) + cost;
    });

    const providerData = Object.entries(costByProvider).map(([provider, cost]) => ({
      provider,
      cost: Math.round(cost * 100) / 100,
      value: Math.round(cost * 100) / 100
    }));
    const modelData = Object.entries(costByModel).map(([model, cost]) => ({ model, cost: Math.round(cost * 100) / 100 }));

    // Daily cost series (last N days window)
    let dailyQuery = supabase
      .from('agent_metrics')
      .select(`
        created_at,
        total_cost,
        agents!inner(organization_id)
      `)
      .eq('client_id', authReq.clientId)
      .gte('created_at', startDate.toISOString())
      .lte('created_at', now.toISOString())
      .order('created_at', { ascending: true });

    if (agent_id) dailyQuery = dailyQuery.eq('agent_id', agent_id);
    if (organization_id) dailyQuery = dailyQuery.eq('agents.organization_id', organization_id);

    const { data: dailyRows, error: dailyErr } = await dailyQuery;

    let daily_costs: Array<{ timestamp: string; cost: number }> = [];
    if (dailyErr) {
      logger.error('Error fetching daily cost series:', dailyErr);
    } else if (dailyRows && dailyRows.length > 0) {
      const buckets: Record<string, number> = {};
      dailyRows.forEach((row: any) => {
        const b = toBucket(row.created_at, true);
        buckets[b] = (buckets[b] || 0) + Number(row.total_cost || 0);
      });

      // Zero-fill missing days for a continuous series
      const series: Array<{ timestamp: string; cost: number }> = [];
      const cur = new Date(startDate);
      cur.setHours(0, 0, 0, 0);
      const end = new Date(now);
      end.setHours(0, 0, 0, 0);
      while (cur <= end) {
        const key = toBucket(cur.toISOString(), true);
        const val = buckets[key] || 0;
        series.push({ timestamp: key, cost: Math.round(val * 100) / 100 });
        cur.setDate(cur.getDate() + 1);
      }
      daily_costs = series;
    }

    res.json({
      total_cost: Math.round(totalCost * 100) / 100,
      cost_by_provider: providerData,
      cost_by_model: modelData,
      daily_costs,
      currency: 'USD'
    });
  } catch (error) {
    logger.error('Analytics cost breakdown endpoint error:', error);
    next(error as any);
  }
});

// GET /api/dashboard/activity - Recent activity data
router.get('/activity', requirePermission('read'), async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { agent_id, organization_id } = req.query as { agent_id?: string; organization_id?: string };

    let errorsQuery = supabase
      .from('agent_errors')
      .select(`
        *,
        agents!inner(agent_id, name, organization_id)
      `)
      .eq('client_id', authReq.clientId)
      .order('created_at', { ascending: false })
      .limit(20);

    if (agent_id) errorsQuery = errorsQuery.eq('agent_id', agent_id);
    if (organization_id) errorsQuery = errorsQuery.eq('agents.organization_id', organization_id);

    const { data: errors, error: errorsError } = await errorsQuery;

    if (errorsError) {
      logger.error('Error fetching activity data:', errorsError);
      res.json({ activities: [] });
      return;
    }

    const activities = errors.map(error => ({
      id: error.id,
      type: 'error',
      message: `${error.agents?.name || 'Agent'}: ${error.error_message}`,
      timestamp: error.created_at,
      severity: error.severity,
      agent_name: error.agents?.name || 'Unknown',
      details: { error_type: error.error_type, resolved: error.resolved }
    }));

    res.json({ activities, total_count: activities.length });
  } catch (error) {
    logger.error('Analytics activity endpoint error:', error);
    next(error as any);
  }
});

export { router as analyticsApiRoutes }; 
