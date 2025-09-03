import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import jwt from 'jsonwebtoken';
import { addTraceContext } from '../middleware/tracing';
import { logger } from '../utils/logger';

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

// Create agent
const createAgent: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const raw = (req.body || {}) as Record<string, any>;

        // Backward-compat for sdk_version -> sdkVersion
        const normalized = {
            ...raw,
            sdkVersion: raw.sdkVersion ?? raw.sdk_version ?? '1.0.0',
        };

        const createAgentSchema = z.object({
            agentName: z.string().min(1),
            agentDescription: z.string().optional(),
            agentType: z.string().min(1),
            agentUseCase: z.string().optional(),
            llmProviders: z.any().optional(),
            platform: z.string().optional(),
            organizationId: z.string().uuid(),
            sdkVersion: z.string().min(1).default('1.0.0'),
        });

        const parsed = createAgentSchema.safeParse(normalized);
        if (!parsed.success) {
            const err: any = new Error('Validation Error');
            err.statusCode = 400; err.name = 'ValidationError';
            (err as any).code = 'ZOD_VALIDATION';
            (err as any).details = parsed.error.issues;
            return next(err);
        }

        const {
            agentName,
            agentDescription,
            agentType,
            agentUseCase,
            llmProviders,
            platform,
            organizationId,
            sdkVersion,
        } = parsed.data;

        // Verify organization belongs to this client
        const { data: org, error: orgError } = await supabase
            .from('organizations')
            .select('id, client_id')
            .eq('id', organizationId)
            .eq('client_id', authReq.clientId)
            .single();
        if (orgError || !org) {
            const err: any = new Error('Organization not found for this client');
            err.statusCode = 404;
            return next(err);
        }

        // Prevent duplicates by name within client+org
        const { data: existing } = await supabase
            .from('agents')
            .select('agent_id')
            .eq('client_id', authReq.clientId)
            .eq('organization_id', organizationId)
            .eq('name', agentName)
            .maybeSingle();
        if (existing?.agent_id) {
            return res.status(409).json({ success: false, error: 'Agent name already exists in this organization', data: { agent_id: existing.agent_id } });
        }

        // Generate unique agent ID
        const agentId = crypto.randomUUID();

        // Prepare agent data
        const agentData = addTraceContext({
            agent_id: agentId,
            client_id: authReq.clientId,
            organization_id: organizationId,
            registration_time: new Date().toISOString(),
            sdk_version: sdkVersion,
            name: agentName,
            description: agentDescription,
            agent_type: agentType,
            platform: platform,
            metadata: {
                useCase: agentUseCase,
                llmProviders: llmProviders,
                createdViaSetup: true
            }
        }, authReq);

        logger.info('Creating agent:', {
            agentId,
            name: agentName,
            type: agentType,
            clientId: authReq.clientId,
            organizationId
        });

        // Insert agent into database
        const { data, error } = await supabase
            .from('agents')
            .insert(agentData)
            .select()
            .single();

        if (error) {
            logger.error('Failed to create agent:', {
                error: error.message,
                agentData: { ...agentData, trace_context: '[REDACTED]' }
            });
            throw error;
        }

        logger.info('Agent created successfully:', {
            agentId: data.agent_id,
            name: data.name
        });

        res.status(201).json({
            success: true,
            data: data
        });

    } catch (error: any) {
        logger.error('Error creating agent:', {
            error: error.message,
            clientId: authReq.clientId
        });
        next(error);
    }
};

// Get agents, optionally filter by organization
const getAgents: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { organization_id } = req.query as { organization_id?: string };
        logger.info('Fetching agents for client:', { clientId: authReq.clientId, organization_id });

        let query = supabase
            .from('agents')
            .select('agent_id, organization_id, name, description, agent_type, platform, status, sdk_version, registration_time, metadata, created_at')
            .eq('client_id', authReq.clientId)
            .order('created_at', { ascending: false });

        if (organization_id) {
            query = query.eq('organization_id', organization_id);
        }

        const { data: agents, error } = await query;

        if (error) {
            logger.error('Failed to fetch agents:', { error: error.message, clientId: authReq.clientId });
            throw error;
        }

        res.json({ success: true, data: agents || [] });

    } catch (error: any) {
        logger.error('Error fetching agents:', { error: error.message, clientId: authReq.clientId });
        next(error);
    }
};

// Delete agent (scoped to client)
const deleteAgent: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { id } = req.params;
        logger.info('Deleting agent:', { agentId: id, clientId: authReq.clientId });

        const { data: deletedRows, error } = await supabase
            .from('agents')
            .delete()
            .eq('agent_id', id)
            .eq('client_id', authReq.clientId)
            .select('agent_id');

        if (error) {
            logger.error('Failed to delete agent:', { error: error.message, agentId: id, clientId: authReq.clientId });
            throw error;
        }

        if (!deletedRows || deletedRows.length === 0) {
            return res.status(404).json({ success: false, error: 'Agent not found' });
        }

        res.json({ success: true, message: 'Agent deleted successfully', data: { deletedCount: deletedRows.length } });

    } catch (error: any) {
        logger.error('Error deleting agent:', { error: error.message, agentId: req.params.id, clientId: authReq.clientId });
        next(error);
    }
};

// Mount the routes with proper middleware
router.post('/', createAgent);
router.get('/', getAgents);
router.delete('/:id', deleteAgent);

export default router; 
