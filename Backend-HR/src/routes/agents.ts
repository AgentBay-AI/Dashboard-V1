import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Create agent
const createAgent: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const {
            agentName,
            agentDescription,
            agentType,
            agentUseCase,
            llmProviders,
            platform,
            organizationId,
            status = 'active',
            sdk_version = '1.0.0'
        } = req.body;

        // Validate required fields
        if (!agentName || !agentType) {
            const err: any = new Error('agentName and agentType are required');
            err.statusCode = 400; err.name = 'ValidationError';
            return next(err);
        }
        if (!organizationId) {
            const err: any = new Error('organizationId is required');
            err.statusCode = 400; err.name = 'ValidationError';
            return next(err);
        }

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

        // Generate unique agent ID
        const agentId = crypto.randomUUID();

        // Prepare agent data
        const agentData = addTraceContext({
            agent_id: agentId,
            client_id: authReq.clientId,
            organization_id: organizationId,
            registration_time: new Date().toISOString(),
            status: status,
            sdk_version: sdk_version,
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
            .select('*')
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

        const { error } = await supabase
            .from('agents')
            .delete()
            .eq('agent_id', id)
            .eq('client_id', authReq.clientId);

        if (error) {
            logger.error('Failed to delete agent:', { error: error.message, agentId: id, clientId: authReq.clientId });
            throw error;
        }

        res.json({ success: true, message: 'Agent deleted successfully' });

    } catch (error: any) {
        logger.error('Error deleting agent:', { error: error.message, agentId: req.params.id, clientId: authReq.clientId });
        next(error);
    }
};

// Mount the routes with proper middleware
router.post('/', requirePermission('write'), createAgent);
router.get('/', requirePermission('read'), getAgents);
router.delete('/:id', requirePermission('write'), deleteAgent);

export default router; 
