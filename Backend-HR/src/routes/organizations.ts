import { Router, Response, Request, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { z } from 'zod';
import { validateSchema } from '../middleware/validation';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import crypto from 'crypto';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

const organizationSchema = z.object({
  orgName: z.string(),
  orgType: z.string(),
  orgDescription: z.string(),
  email: z.string().email(),
});

// Create organization
const createOrganization: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  try {
    // Body already validated by validateSchema middleware
    const { orgName, orgType, orgDescription, email } = req.body as z.infer<typeof organizationSchema>;

    // Ensure the client's key exists and is active (self-heal if needed)
    try {
      const { data: key, error: keyErr } = await supabase
        .from('api_keys')
        .select('*')
        .eq('client_id', authReq.clientId)
        .eq('is_active', true)
        .maybeSingle();
      if (keyErr || !key) {
        const rawKey = `sk-${crypto.randomBytes(32).toString('hex')}`;
        const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
        await supabase.from('api_keys').upsert({
          client_id: authReq.clientId,
          key_hash: keyHash,
          client_name: `${email || 'User'} Dashboard`,
          permissions: JSON.stringify(["read","write","sdk","admin"]),
          rate_limit_per_minute: 3000,
          is_active: true,
          verified: true,
          verified_at: new Date().toISOString()
        }, { onConflict: 'client_id' });
      }
    } catch {}

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
      .from('view_organization_overview')
      .select('*')
      .eq('client_id', authReq.clientId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    res.json({ success: true, data: organizations });
  } catch (error: any) {
    next(error);
  }
};

router.post('/', requirePermission('write'), validateSchema(organizationSchema), createOrganization);
router.get('/', requirePermission('read'), getOrganizations);

export default router; 
