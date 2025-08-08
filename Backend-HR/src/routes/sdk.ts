import { Router, Request, Response, RequestHandler } from 'express';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';
import { calculateTokenCost } from '../config/llm-pricing';

const router = Router();
router.use(authenticateApiKey);

// Helpers
async function resolveProviderIfMissing(model?: string): Promise<string | undefined> {
  if (!model) return undefined;
  const { data, error } = await supabase
    .from('llm_models')
    .select('provider')
    .eq('model', String(model).toLowerCase())
    .single();
  if (error) return undefined;
  return data?.provider;
}

// Schemas
const llmUsageSchema = z.object({
  agent_id: z.string().uuid(),
  session_id: z.string().uuid(),
  timestamp: z.string().datetime().optional(),
  provider: z.string().optional(),
  model: z.string().optional(),
  tokens_input: z.number().int().nonnegative().default(0),
  tokens_output: z.number().int().nonnegative().default(0),
  cost: z.number().nonnegative().optional(),
});

const metricsSchema = z.object({
  agent_id: z.string().uuid(),
  total_tokens: z.number().int().nonnegative().default(0),
  input_tokens: z.number().int().nonnegative().default(0),
  output_tokens: z.number().int().nonnegative().default(0),
  total_cost: z.number().nonnegative().default(0),
  total_requests: z.number().int().nonnegative().default(1),
  average_latency: z.number().int().nonnegative().default(0),
  success_rate: z.number().int().min(0).max(100).default(100),
  created_at: z.string().datetime().optional(),
});

const healthSchema = z.object({
  agent_id: z.string().uuid(),
  status: z.string().default('healthy'),
  uptime: z.number().int().min(0).max(100).default(100),
  response_time: z.number().int().nonnegative().default(0),
  error_rate: z.number().int().min(0).max(100).default(0),
  cpu_usage: z.number().int().min(0).max(100).default(0),
  memory_usage: z.number().int().min(0).max(100).default(0),
  created_at: z.string().datetime().optional(),
});

const errorSchema = z.object({
  agent_id: z.string().uuid(),
  error_type: z.string(),
  error_message: z.string(),
  severity: z.enum(['low','medium','high']).default('low'),
  resolved: z.boolean().default(false),
  created_at: z.string().datetime().optional(),
});

const conversationStartSchema = z.object({
  session_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  start_time: z.string().datetime().optional(),
  metadata: z.record(z.any()).optional(),
});

const conversationEndSchema = z.object({
  session_id: z.string().uuid(),
  end_time: z.string().datetime().optional(),
  status: z.enum(['ended','failed','timeout','abandoned']).default('ended'),
});

const messageSchema = z.object({
  session_id: z.string().uuid(),
  role: z.enum(['user','assistant','system']),
  content: z.string(),
  timestamp: z.string().datetime().optional(),
  metadata: z.record(z.any()).optional(),
});

// Verify agent belongs to client
async function assertAgentOwnedByClient(clientId: string, agentId: string): Promise<boolean> {
  const { data } = await supabase
    .from('agents')
    .select('agent_id, client_id')
    .eq('agent_id', agentId)
    .eq('client_id', clientId)
    .single();
  return !!data;
}

// POST /api/sdk/llm-usage
const postLlmUsage: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = llmUsageSchema.parse(req.body);
    const owned = await assertAgentOwnedByClient(authReq.clientId, body.agent_id);
    if (!owned) return res.status(404).json({ success: false, error: 'Agent not found for this client' });

    let provider = body.provider?.toLowerCase();
    const model = body.model?.toLowerCase();
    if (!provider && model) provider = await resolveProviderIfMissing(model);

    let cost = body.cost;
    if ((!cost || cost === 0) && provider && model) {
      cost = calculateTokenCost(provider, model, body.tokens_input, body.tokens_output);
    }

    const { error } = await supabase.from('llm_usage').insert({
      session_id: body.session_id,
      agent_id: body.agent_id,
      client_id: authReq.clientId,
      timestamp: body.timestamp || new Date().toISOString(),
      provider: provider,
      model: model,
      tokens_input: body.tokens_input,
      tokens_output: body.tokens_output,
      cost: cost || 0,
    });

    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK llm-usage error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/metrics
const postMetrics: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = metricsSchema.parse(req.body);
    const owned = await assertAgentOwnedByClient(authReq.clientId, body.agent_id);
    if (!owned) return res.status(404).json({ success: false, error: 'Agent not found for this client' });

    const { error } = await supabase.from('agent_metrics').insert({
      id: crypto.randomUUID(),
      agent_id: body.agent_id,
      client_id: authReq.clientId,
      total_tokens: body.total_tokens,
      input_tokens: body.input_tokens,
      output_tokens: body.output_tokens,
      total_cost: body.total_cost,
      total_requests: body.total_requests,
      average_latency: body.average_latency,
      success_rate: body.success_rate,
      created_at: body.created_at || new Date().toISOString(),
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK metrics error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/health
const postHealth: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = healthSchema.parse(req.body);
    const owned = await assertAgentOwnedByClient(authReq.clientId, body.agent_id);
    if (!owned) return res.status(404).json({ success: false, error: 'Agent not found for this client' });

    const { error } = await supabase.from('agent_health').insert({
      id: crypto.randomUUID(),
      agent_id: body.agent_id,
      client_id: authReq.clientId,
      status: body.status,
      uptime: body.uptime,
      last_ping: new Date().toISOString(),
      response_time: body.response_time,
      error_rate: body.error_rate,
      cpu_usage: body.cpu_usage,
      memory_usage: body.memory_usage,
      created_at: body.created_at || new Date().toISOString(),
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK health error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/error
const postError: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = errorSchema.parse(req.body);
    const owned = await assertAgentOwnedByClient(authReq.clientId, body.agent_id);
    if (!owned) return res.status(404).json({ success: false, error: 'Agent not found for this client' });

    const { error } = await supabase.from('agent_errors').insert({
      id: crypto.randomUUID(),
      agent_id: body.agent_id,
      client_id: authReq.clientId,
      error_type: body.error_type,
      error_message: body.error_message,
      severity: body.severity,
      resolved: body.resolved,
      created_at: body.created_at || new Date().toISOString(),
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK error log error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/conversations/start
const postConversationStart: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = conversationStartSchema.parse(req.body);
    const owned = await assertAgentOwnedByClient(authReq.clientId, body.agent_id);
    if (!owned) return res.status(404).json({ success: false, error: 'Agent not found for this client' });

    // Upsert-like behavior: try insert; if exists, ignore
    const { error } = await supabase.from('conversations').insert({
      session_id: body.session_id,
      agent_id: body.agent_id,
      client_id: authReq.clientId,
      start_time: body.start_time || new Date().toISOString(),
      status: 'started',
      metadata: body.metadata || {},
    });
    if (error && !String(error.message).includes('duplicate key')) throw error;

    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK conversation start error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/conversations/end
const postConversationEnd: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = conversationEndSchema.parse(req.body);
    const { error } = await supabase
      .from('conversations')
      .update({ end_time: body.end_time || new Date().toISOString(), status: body.status })
      .eq('session_id', body.session_id)
      .eq('client_id', authReq.clientId);
    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK conversation end error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

// POST /api/sdk/messages
const postMessage: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const body = messageSchema.parse(req.body);
    const { error } = await supabase.from('messages').insert({
      session_id: body.session_id,
      timestamp: body.timestamp || new Date().toISOString(),
      content: body.content,
      role: body.role,
      metadata: body.metadata || {},
      client_id: authReq.clientId,
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (err: any) {
    logger.error('SDK message error:', err);
    res.status(400).json({ success: false, error: err.message });
  }
};

router.post('/llm-usage', requirePermission('write'), postLlmUsage);
router.post('/metrics', requirePermission('write'), postMetrics);
router.post('/health', requirePermission('write'), postHealth);
router.post('/error', requirePermission('write'), postError);
router.post('/conversations/start', requirePermission('write'), postConversationStart);
router.post('/conversations/end', requirePermission('write'), postConversationEnd);
router.post('/messages', requirePermission('write'), postMessage);

export default router; 