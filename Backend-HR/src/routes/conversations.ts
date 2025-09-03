import { Router, Request, Response, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateApiKey, AuthenticatedRequest } from '../middleware/auth';
import jwt from 'jsonwebtoken';
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
router.get('/', getConversations);

export default router; 
