import express from 'express';
import { authenticateApiKey, requirePermission } from '../middleware/auth';
import { validateSchema } from '../middleware/validation';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { addTraceContext } from '../middleware/tracing';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Start conversation
router.post('/start', async (req, res) => {
    try {
        const data = addTraceContext(req.body, req);
        
        const { error } = await supabase
            .from('conversations')
            .insert(data);

        if (error) {
            logger.error('Failed to start conversation:', error);
            return res.status(500).json({
                error: 'Start failed',
                message: error.message
            });
        }

        res.status(201).json({
            message: 'Conversation started successfully'
        });
    } catch (error: any) {
        logger.error('Conversation start error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Add message
router.post('/message', async (req, res) => {
    try {
        const data = addTraceContext(req.body, req);
        
        const { error } = await supabase
            .from('messages')
            .insert(data);

        if (error) {
            logger.error('Failed to add message:', error);
            return res.status(500).json({
                error: 'Message add failed',
                message: error.message
            });
        }

        res.status(200).json({
            message: 'Message added successfully'
        });
    } catch (error: any) {
        logger.error('Message add error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// End conversation
router.post('/end', async (req, res) => {
    try {
        const data = addTraceContext(req.body, req);
        
        const { error } = await supabase
            .from('conversations')
            .update({
                status: 'completed',
                end_time: new Date().toISOString(),
                ...data
            })
            .eq('session_id', data.session_id);

        if (error) {
            logger.error('Failed to end conversation:', error);
            return res.status(500).json({
                error: 'End failed',
                message: error.message
            });
        }

        res.status(200).json({
            message: 'Conversation ended successfully'
        });
    } catch (error: any) {
        logger.error('Conversation end error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Get active conversations
router.get('/active', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('conversations')
            .select('*')
            .eq('status', 'active');

        if (error) {
            logger.error('Failed to get active conversations:', error);
            return res.status(500).json({
                error: 'Query failed',
                message: error.message
            });
        }

        res.json(data);
    } catch (error: any) {
        logger.error('Active conversations query error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

export default router; 