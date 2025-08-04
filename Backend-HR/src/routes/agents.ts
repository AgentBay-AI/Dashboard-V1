import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { supabase } from '../lib/supabase';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Create a new agent
router.post('/', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
    try {
        const { 
            agentName, 
            agentDescription, 
            agentType, 
            agentUseCase, 
            llmProviders, 
            platform 
        } = req.body;
        
        // Validate required fields
        if (!agentName || !agentType) {
            return res.status(400).json({
                success: false,
                error: 'Agent name and type are required'
            });
        }

        // Generate unique ID
        const agentId = uuidv4();

        // Insert into agents table
        const { data, error } = await supabase
            .from('agents')
            .insert({
                agent_id: agentId,
                client_id: req.clientId,
                registration_time: new Date().toISOString(),
                status: 'active',
                sdk_version: '1.0.0',
                metadata: {
                    name: agentName,
                    description: agentDescription,
                    type: agentType,
                    useCase: agentUseCase,
                    llmProviders: llmProviders,
                    platform: platform,
                    createdViaSetup: true
                }
            })
            .select()
            .single();

        if (error) {
            logger.error('Failed to create agent:', error);
            console.error('Supabase error details:', JSON.stringify(error, null, 2));
            return res.status(500).json({
                success: false,
                error: 'Failed to create agent',
                details: error.message
            });
        }

        // TODO: Create initial agent status after fixing table schema
        // const { error: statusError } = await supabase
        //     .from('agent_status')
        //     .insert({
        //         agent_id: agentId,
        //         status: 'online',
        //         client_id: req.clientId
        //     });

        // if (statusError) {
        //     logger.error('Failed to create agent status:', statusError);
        // }

        res.json({
            success: true,
            data: {
                id: agentId,
                agent_id: agentId,
                name: agentName,
                description: agentDescription,
                type: agentType,
                capabilities: agentUseCase,
                llm_providers: llmProviders,
                platform: platform,
                status: 'active',
                metadata: data.metadata
            }
        });
    } catch (error: any) {
        logger.error('Create agent error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// List all agents for the client
router.get('/', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
    try {
        const { data, error } = await supabase
            .from('agents')
            .select('*')
            .eq('client_id', req.clientId);

        if (error) {
            logger.error('Failed to list agents:', error);
            console.error('List agents error details:', JSON.stringify(error, null, 2));
            return res.status(500).json({
                success: false,
                error: 'Failed to list agents',
                details: error.message
            });
        }

        res.json({
            success: true,
            data: data || []
        });
    } catch (error: any) {
        logger.error('List agents error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Delete an agent
router.delete('/:id', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
    try {
        const { id } = req.params;

        // First verify the agent belongs to this client
        const { data: agent, error: checkError } = await supabase
            .from('agents')
            .select('id')
            .eq('id', id)
            .eq('client_id', req.clientId)
            .single();

        if (checkError || !agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Delete the agent
        const { error } = await supabase
            .from('agents')
            .delete()
            .eq('id', id)
            .eq('client_id', req.clientId);

        if (error) {
            logger.error('Failed to delete agent:', error);
            return res.status(500).json({
                success: false,
                error: 'Failed to delete agent'
            });
        }

        res.json({
            success: true,
            data: { id }
        });
    } catch (error: any) {
        logger.error('Delete agent error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

export default router; 