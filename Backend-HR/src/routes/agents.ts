import { Router, Request, Response, RequestHandler } from 'express';
import crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Create agent
const createAgent: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const {
            agentName,
            agentDescription,
            agentType,
            agentUseCase,
            llmProviders,
            platform,
            status = 'active',
            sdk_version = '1.0.0'
        } = req.body;

        // Validate required fields
        if (!agentName || !agentType) {
            return res.status(400).json({
                success: false,
                error: 'agentName and agentType are required'
            });
        }

        // Generate unique agent ID
        const agentId = crypto.randomUUID();

        // Prepare agent data
        const agentData = addTraceContext({
            agent_id: agentId,
            client_id: authReq.clientId,
            registration_time: new Date().toISOString(),
            status: status,
            sdk_version: sdk_version,
            metadata: {
                name: agentName,
                description: agentDescription,
                type: agentType,
                useCase: agentUseCase,
                platform: platform,
                llmProviders: llmProviders,
                createdViaSetup: true
            }
        }, authReq);

        logger.info('Creating agent:', {
            agentId,
            name: agentName,
            type: agentType,
            clientId: authReq.clientId
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
        
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Get all agents for client
const getAgents: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        logger.info('Fetching agents for client:', { clientId: authReq.clientId });

        const { data: agents, error } = await supabase
            .from('agents')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('created_at', { ascending: false });

        if (error) {
            logger.error('Failed to fetch agents:', {
                error: error.message,
                clientId: authReq.clientId
            });
            throw error;
        }

        logger.info('Agents fetched successfully:', {
            count: agents?.length || 0,
            clientId: authReq.clientId
        });

        res.json({
            success: true,
            data: agents || []
        });

    } catch (error: any) {
        logger.error('Error fetching agents:', {
            error: error.message,
            clientId: authReq.clientId
        });
        
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Delete agent
const deleteAgent: RequestHandler = async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { id } = req.params;
        
        logger.info('Deleting agent:', {
            agentId: id,
            clientId: authReq.clientId
        });

        // Delete agent (cascading will handle related records)
        const { error } = await supabase
            .from('agents')
            .delete()
            .eq('agent_id', id)
            .eq('client_id', authReq.clientId);

        if (error) {
            logger.error('Failed to delete agent:', {
                error: error.message,
                agentId: id,
                clientId: authReq.clientId
            });
            throw error;
        }

        logger.info('Agent deleted successfully:', {
            agentId: id,
            clientId: authReq.clientId
        });

        res.json({
            success: true,
            message: 'Agent deleted successfully'
        });

    } catch (error: any) {
        logger.error('Error deleting agent:', {
            error: error.message,
            agentId: req.params.id,
            clientId: authReq.clientId
        });
        
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

// Mount the routes with proper middleware
router.post('/', requirePermission('write'), createAgent);
router.get('/', requirePermission('read'), getAgents);
router.delete('/:id', requirePermission('write'), deleteAgent);

export default router; 