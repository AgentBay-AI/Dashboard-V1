import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { z } from 'zod';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all uptime routes
router.use(authenticateApiKey);

// Heartbeat schema (validation-only; no DB persistence yet)
const heartbeatSchema = z.object({
  agent_id: z.string().uuid(),
  instance_id: z.string().min(1),
  status: z.enum(['up','down','starting','stopping','unknown']).default('up'),
  timestamp: z.string().datetime().optional(),
  process_start_ts: z.string().datetime().optional(),
  uptime_ms: z.number().int().nonnegative().optional(),
  expected_interval_s: z.number().int().min(1).max(3600).optional(),
  metadata: z.record(z.any()).optional(),
});

// Verify agent belongs to client (duplicated from sdk.ts)
async function assertAgentOwnedByClient(clientId: string, agentId: string): Promise<boolean> {
  const { data } = await supabase
    .from('agents')
    .select('agent_id, client_id')
    .eq('agent_id', agentId)
    .eq('client_id', clientId)
    .single();
  return !!data;
}

function toMinuteBucket(d: Date): string {
  const dd = new Date(d);
  dd.setSeconds(0, 0);
  return dd.toISOString();
}

function getExpectedCount(expectedInterval?: number): number {
  const interval = Math.max(1, Math.min(3600, expectedInterval || 2));
  return Math.max(1, Math.floor(60 / interval));
}

// POST /agents/heartbeat
const postHeartbeat: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  const clientId = authReq.clientId || '';
  if (!clientId) {
    const e: any = new Error('Missing client');
    e.statusCode = 401; e.name = 'UnauthorizedError';
    return next(e);
  }
  try {
    const parsed = heartbeatSchema.safeParse(req.body);
    if (!parsed.success) {
      const e: any = new Error('Validation Error');
      e.statusCode = 400; e.name = 'ValidationError';
      (e as any).code = 'ZOD_VALIDATION';
      (e as any).details = parsed.error.issues;
      return next(e);
    }
    const body = parsed.data;

    // Optional client cross-check header
    const hdrClient = (req.headers['x-client-id'] as string | undefined)?.trim();
    if (hdrClient && hdrClient !== clientId) {
      const e: any = new Error('Client header mismatch for this key');
      e.statusCode = 400; e.name = 'ValidationError';
      return next(e);
    }

    const owned = await assertAgentOwnedByClient(clientId, body.agent_id);
    if (!owned) {
      const e: any = new Error('Agent not found for this client');
      e.statusCode = 404; e.name = 'NotFoundError';
      return next(e);
    }

    const now = new Date();
    const bucketMin = toMinuteBucket(now);
    const expectedCount = getExpectedCount(body.expected_interval_s);
    let lastSeen = now.toISOString();

    // Try RPC-based atomic increment first (requires SQL function inc_uptime_minute)
    try {
      const { error: rpcErr } = await supabase.rpc('inc_uptime_minute', {
        p_client_id: clientId,
        p_agent_id: body.agent_id,
        p_instance_id: body.instance_id,
        p_bucket_min: bucketMin,
        p_expected_count: expectedCount,
        p_last_seen: lastSeen,
      });
      if (rpcErr) throw rpcErr;
    } catch (rpcErr: any) {
      // Fallback to non-atomic upsert: select then insert/update
      logger.debug?.('RPC inc_uptime_minute unavailable, falling back to manual upsert', { error: rpcErr?.message });
      try {
        const { data: existing } = await supabase
          .from('agent_uptime_minute')
          .select('received_count')
          .eq('client_id', clientId)
          .eq('agent_id', body.agent_id)
          .eq('instance_id', body.instance_id)
          .eq('bucket_min', bucketMin)
          .maybeSingle();

        if (existing) {
          const { error: updErr } = await supabase
            .from('agent_uptime_minute')
            .update({
              received_count: (existing.received_count || 0) + 1,
              expected_count: expectedCount,
              last_seen: lastSeen,
            })
            .eq('client_id', clientId)
            .eq('agent_id', body.agent_id)
            .eq('instance_id', body.instance_id)
            .eq('bucket_min', bucketMin);
          if (updErr) throw updErr;
        } else {
          const { error: insErr } = await supabase
            .from('agent_uptime_minute')
            .insert({
              client_id: clientId,
              agent_id: body.agent_id,
              instance_id: body.instance_id,
              bucket_min: bucketMin,
              received_count: 1,
              expected_count: expectedCount,
              last_seen: lastSeen,
            });
          if (insErr) throw insErr;
        }
      } catch (fallErr: any) {
        // If the minute table doesn't exist yet, just proceed without persistence
        if (String(fallErr?.code) !== '42P01') {
          logger.error('Manual minute upsert failed:', fallErr);
        } else {
          logger.warn('agent_uptime_minute table not found; skipping persistence');
        }
      }
    }

    // Respond with acceptance
    res.json({
      success: true,
      data: {
        client_id: clientId,
        agent_id: body.agent_id,
        instance_id: body.instance_id,
        status: body.status,
        last_seen: lastSeen,
        message: 'Heartbeat accepted',
      }
    });
  } catch (err: any) {
    logger.error('Uptime heartbeat error:', err);
    next(err);
  }
};

router.post('/agents/heartbeat', requirePermission('write'), postHeartbeat);

// GET /api/uptime/summary?window=24h&agent_id=&organization_id=
const getSummary: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  const clientId = authReq.clientId || '';
  if (!clientId) {
    const e: any = new Error('Missing client'); e.statusCode = 401; e.name = 'UnauthorizedError';
    return next(e);
  }
  try {
    const { window = '24h', agent_id, organization_id } = req.query as { window?: string; agent_id?: string; organization_id?: string };
    const hours = parseInt(String(window), 10) || 24;
    const useDaily = hours > 24;
    const now = new Date();
    const start = new Date(now);
    start.setHours(start.getHours() - hours);

    let agentIds: string[] | undefined = undefined;
    if (organization_id) {
      const { data: orgAgents } = await supabase
        .from('agents')
        .select('agent_id')
        .eq('client_id', clientId)
        .eq('organization_id', organization_id);
      agentIds = (orgAgents || []).map(a => a.agent_id);
      if (agentIds.length === 0) return res.json({ data: [] });
    }

    if (!useDaily) {
      // Aggregate from hourly
      let q = supabase
        .from('agent_uptime_hourly')
        .select('*')
        .eq('client_id', clientId)
        .gte('bucket_hour', start.toISOString())
        .lte('bucket_hour', now.toISOString());
      if (agent_id) q = q.eq('agent_id', agent_id);
      if (agentIds) q = q.in('agent_id', agentIds);

      const { data: rows, error } = await q;
      if (error) {
        if ((error as any).code === '42P01') return res.json({ data: [] });
        throw error;
      }
      // Group by agent
      const byAgent = new Map<string, { rc: number; ec: number; last_seen?: string }>();
      for (const r of rows || []) {
        const k = r.agent_id as string;
        const entry = byAgent.get(k) || { rc: 0, ec: 0, last_seen: undefined };
        entry.rc += Number(r.received_count || 0);
        entry.ec += Number(r.expected_count || 0);
        if (r.last_seen && (!entry.last_seen || r.last_seen > entry.last_seen)) entry.last_seen = r.last_seen;
        byAgent.set(k, entry);
      }
      const data = Array.from(byAgent.entries()).map(([aid, v]) => ({
        agent_id: aid,
        uptime_pct: v.ec > 0 ? Math.round((v.rc / v.ec) * 10000) / 100 : 0,
        last_seen: v.last_seen || null,
      }));
      return res.json({ data });
    } else {
      // Aggregate from daily
      const days = Math.ceil(hours / 24);
      const startDay = new Date(now);
      startDay.setDate(startDay.getDate() - days);
      startDay.setHours(0, 0, 0, 0);

      let q = supabase
        .from('agent_uptime_daily')
        .select('*')
        .eq('client_id', clientId)
        .gte('bucket_day', startDay.toISOString())
        .lte('bucket_day', now.toISOString());
      if (agent_id) q = q.eq('agent_id', agent_id);
      if (agentIds) q = q.in('agent_id', agentIds);

      const { data: rows, error } = await q;
      if (error) {
        if ((error as any).code === '42P01') return res.json({ data: [] });
        throw error;
      }
      const byAgent = new Map<string, { rc: number; ec: number }>();
      for (const r of rows || []) {
        const k = r.agent_id as string;
        const entry = byAgent.get(k) || { rc: 0, ec: 0 };
        entry.rc += Number(r.received_hours || 0);
        entry.ec += Number(r.expected_hours || 0);
        byAgent.set(k, entry);
      }
      const data = Array.from(byAgent.entries()).map(([aid, v]) => ({
        agent_id: aid,
        uptime_pct: v.ec > 0 ? Math.round((v.rc / v.ec) * 10000) / 100 : 0,
      }));
      return res.json({ data });
    }
  } catch (err) {
    logger.error('Uptime summary error:', err);
    next(err as any);
  }
};

// GET /api/uptime/timeseries?agent_id=...&window=24h&bucket=minute|hour|day
const getTimeseries: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  const clientId = authReq.clientId || '';
  if (!clientId) { const e: any = new Error('Missing client'); e.statusCode = 401; e.name = 'UnauthorizedError'; return next(e); }
  try {
    const { agent_id, window = '24h', bucket } = req.query as { agent_id?: string; window?: string; bucket?: 'minute'|'hour'|'day' };
    if (!agent_id) return res.status(400).json({ error: 'agent_id is required' });
    const hours = parseInt(String(window), 10) || 24;
    const now = new Date();
    const start = new Date(now);
    start.setHours(start.getHours() - hours);

    const chosenBucket = bucket || (hours <= 3 ? 'minute' : hours <= 168 ? 'hour' : 'day');

    if (chosenBucket === 'minute') {
      let q = supabase
        .from('agent_uptime_minute')
        .select('bucket_min, received_count, expected_count')
        .eq('client_id', clientId)
        .eq('agent_id', agent_id)
        .gte('bucket_min', start.toISOString())
        .lte('bucket_min', now.toISOString())
        .order('bucket_min', { ascending: true });
      const { data: rows, error } = await q;
      if (error) { if ((error as any).code === '42P01') return res.json({ data: [] }); throw error; }
      const data = (rows || []).map((r: any) => ({
        timestamp: r.bucket_min,
        uptime_pct: r.expected_count > 0 ? Math.round((r.received_count / r.expected_count) * 10000) / 100 : 0,
      }));
      return res.json({ data });
    }

    if (chosenBucket === 'hour') {
      let q = supabase
        .from('agent_uptime_hourly')
        .select('bucket_hour, received_count, expected_count')
        .eq('client_id', clientId)
        .eq('agent_id', agent_id)
        .gte('bucket_hour', start.toISOString())
        .lte('bucket_hour', now.toISOString())
        .order('bucket_hour', { ascending: true });
      const { data: rows, error } = await q;
      if (error) { if ((error as any).code === '42P01') return res.json({ data: [] }); throw error; }
      const data = (rows || []).map((r: any) => ({
        timestamp: r.bucket_hour,
        uptime_pct: r.expected_count > 0 ? Math.round((r.received_count / r.expected_count) * 10000) / 100 : 0,
      }));
      return res.json({ data });
    }

    // day
    {
      const days = Math.ceil(hours / 24);
      const startDay = new Date(now);
      startDay.setDate(startDay.getDate() - days);
      startDay.setHours(0, 0, 0, 0);
      let q = supabase
        .from('agent_uptime_daily')
        .select('bucket_day, received_hours, expected_hours')
        .eq('client_id', clientId)
        .eq('agent_id', agent_id)
        .gte('bucket_day', startDay.toISOString())
        .lte('bucket_day', now.toISOString())
        .order('bucket_day', { ascending: true });
      const { data: rows, error } = await q;
      if (error) { if ((error as any).code === '42P01') return res.json({ data: [] }); throw error; }
      const data = (rows || []).map((r: any) => ({
        timestamp: r.bucket_day,
        uptime_pct: r.expected_hours > 0 ? Math.round((r.received_hours / r.expected_hours) * 10000) / 100 : 0,
      }));
      return res.json({ data });
    }
  } catch (err) {
    logger.error('Uptime timeseries error:', err);
    next(err as any);
  }
};

router.get('/summary', requirePermission('read'), getSummary);
router.get('/timeseries', requirePermission('read'), getTimeseries);

export default router;
