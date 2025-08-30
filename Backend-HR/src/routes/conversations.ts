import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get conversations
const getConversations: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const { data: conversations, error } = await supabase
            .from('conversations')
            .select('*')
            .eq('client_id', authReq.clientId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({
            success: true,
            data: conversations || []
        });

    } catch (error: any) {
        logger.error('Error fetching conversations:', error);
        next(error);
    }
};

// Mount routes
router.get('/', requirePermission('read'), getConversations);

export default router; 
