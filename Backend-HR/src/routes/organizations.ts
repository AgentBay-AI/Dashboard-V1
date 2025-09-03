import { Router, Response, Request, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { z } from 'zod';
import { validateSchema } from '../middleware/validation';
import { AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import jwt from 'jsonwebtoken';

const router = Router();

// Resolve client identity from either a user JWT (dashboard) or API key (SDK)
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev-only-secret' : undefined as any);

const resolveClientId: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers['authorization'];
    const raw = Array.isArray(authHeader) ? authHeader[0] : authHeader;
    // Dev override: allow x-client-id if no Authorization and not production
    if (!raw) {
      if (process.env.NODE_ENV !== 'production') {
        const override = (req.headers['x-client-id'] as string | undefined)?.trim();
        if (override) {
          (req as AuthenticatedRequest).clientId = override;
          return next();
        }
      }
      return res.status(401).json({ error: 'Missing authorization' });
    }

    // Bearer token expected
    let token = raw.startsWith('Bearer ') ? raw.slice(7) : raw;

    // If token looks like an API key (sk-...), use API key middleware
    if (token.startsWith('sk-')) {
      // Delegate to existing API key middleware
      return authenticateApiKey(req, res, next);
    }

    // Otherwise, treat as user JWT and extract clientId claim
    if (!JWT_SECRET) return res.status(401).json({ error: 'Server auth not configured' });
    const decoded: any = jwt.verify(token, JWT_SECRET);
    let cid: string | undefined = decoded?.clientId;
    if (!cid || typeof cid !== 'string' || cid.trim().length === 0) {
      // Fallback: resolve client_id from email in Clerk JWT template
      const email: string | undefined = (decoded?.email || decoded?.email_address || (Array.isArray(decoded?.email_addresses) ? decoded.email_addresses[0]?.email_address : undefined));
      if (email && typeof email === 'string') {
        const { data: profile } = await supabase
          .from('profiles')
          .select('client_id')
          .eq('email', email.toLowerCase())
          .maybeSingle();
        cid = profile?.client_id;
      }
    }
    if (!cid || typeof cid !== 'string' || cid.trim().length === 0) {
      return res.status(401).json({ error: 'Invalid token: clientId missing' });
    }
    (req as AuthenticatedRequest).clientId = cid;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

// Apply client resolution to all routes in this router
router.use(resolveClientId);

// Input validation and normalization
const organizationSchema = z.object({
  orgName: z.string().trim().min(2, 'Organization name is too short').max(100, 'Organization name is too long'),
  // Align accepted values with the frontend select options
  orgType: z.enum(['startup', 'enterprise', 'agency', 'consulting', 'nonprofit', 'education']).transform(v => v.toLowerCase()),
  // Allow empty but cap length to avoid abuse; trim whitespace
  orgDescription: z.string().trim().max(1000, 'Description is too long').default(''),
  email: z.string().trim().email('Invalid email').max(254, 'Email is too long'),
});

// Create organization
const createOrganization: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  try {
    // Body already validated/normalized by validateSchema middleware
    const { orgName, orgType, orgDescription } = req.body as z.infer<typeof organizationSchema>;

    // Guard against duplicate organization names for the same client
    const { count: nameCount, error: lookupErr } = await supabase
      .from('organizations')
      .select('id', { count: 'exact', head: true })
      .eq('client_id', authReq.clientId)
      .eq('name', orgName);
    if (lookupErr) throw lookupErr;
    if ((nameCount || 0) > 0) {
      return res.status(409).json({ success: false, error: 'Organization name already exists for this account' });
    }

    const { data, error } = await supabase
      .from('organizations')
      .insert(addTraceContext({
        name: orgName,
        plan: orgType,
        client_id: authReq.clientId,
        description: orgDescription
      }, authReq))
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ success: true, data });
  } catch (error: any) {
    next(error);
  }
};

// Get organizations for client (overview)
const getOrganizations: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const { data: organizations, error } = await supabase
      .from('organizations')
      .select('*')
      .eq('client_id', authReq.clientId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    res.json({ success: true, data: organizations });
  } catch (error: any) {
    next(error);
  }
};

router.post('/', validateSchema(organizationSchema), createOrganization);
router.get('/', getOrganizations);

export default router; 
