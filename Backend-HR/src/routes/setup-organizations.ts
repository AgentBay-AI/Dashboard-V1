import { Router, Response, Request, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { z } from 'zod';
import crypto from 'crypto';
import { addTraceContext } from '../middleware/tracing';
import jwt from 'jsonwebtoken';

const router = Router();

// Temporary setup endpoint - should be removed in production
const setupOrganizations: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthenticatedRequest;
  try {
    console.log('🚀 Starting organizations setup...');

    // Try to check if table exists by querying it
    const { data: existingOrgs, error: checkError } = await supabase
      .from('organizations')
      .select('*')
      .limit(1);

    if (checkError && checkError.code === '42P01') {
      // Table doesn't exist - this means we need to create it in Supabase dashboard
      return res.status(500).json({
        success: false,
        error: 'Organizations table does not exist. Please create it manually in Supabase.',
        instructions: [
          '1. Go to your Supabase dashboard',
          '2. Navigate to SQL Editor',
          '3. Run the SQL script from add-organizations.sql',
          '4. Then try this endpoint again'
        ]
      });
    }

    // If we get here, table exists or we have a different error
    if (checkError) {
      throw checkError;
    }

    // Add sample organizations if table is empty
    if (!existingOrgs || existingOrgs.length === 0) {
      console.log('📦 Adding sample organizations...');
      
      const sampleOrgs = [
        {
          name: 'TechCorp Inc',
          plan: 'Enterprise',
          client_id: authReq.clientId,
          metadata: {
            description: 'Technology company',
            email: 'contact@techcorp.com',
            type: 'enterprise'
          }
        },
        {
          name: 'SalesForce Ltd',
          plan: 'Professional',
          client_id: authReq.clientId,
          metadata: {
            description: 'Sales automation company',
            email: 'contact@salesforce.com',
            type: 'professional'
          }
        },
        {
          name: 'HR Solutions',
          plan: 'Basic',
          client_id: authReq.clientId,
          metadata: {
            description: 'Human resources company',
            email: 'contact@hrsolutions.com',
            type: 'startup'
          }
        },
        {
          name: 'MarketingPro',
          plan: 'Professional',
          client_id: authReq.clientId,
          metadata: {
            description: 'Marketing agency',
            email: 'contact@marketingpro.com',
            type: 'professional'
          }
        }
      ];

      const { data: insertedOrgs, error: insertError } = await supabase
        .from('organizations')
        .insert(sampleOrgs)
        .select();

      if (insertError) {
        throw insertError;
      }

      console.log(`✅ Created ${insertedOrgs.length} organizations`);
    }

    // Get all organizations for this client
    const { data: allOrgs, error: fetchError } = await supabase
      .from('organizations')
      .select('*')
      .eq('client_id', authReq.clientId);

    if (fetchError) {
      throw fetchError;
    }

    res.json({
      success: true,
      message: 'Organizations setup completed',
      data: allOrgs
    });

  } catch (error: any) {
    console.error('❌ Organizations setup failed:', error);
    next(error);
  }
};

router.post('/setup-organizations', requirePermission('write'), setupOrganizations);

// Helper: generate a short unique client id
async function generateShortClientId(): Promise<string> {
  for (let i = 0; i < 5; i++) {
    const candidate = `c-${crypto.randomBytes(3).toString('hex')}`;
    const { data: exists } = await supabase
      .from('api_keys')
      .select('id')
      .eq('client_id', candidate)
      .maybeSingle();
    if (!exists) return candidate;
  }
  return `c-${crypto.randomBytes(6).toString('hex')}`;
}

// Removed legacy bootstrap route to simplify first-run flow

// Simple first-run organization creation (no API key flow)
const simpleOrgSchema = z.object({
  email: z.string().trim().email('Invalid email').max(254, 'Email too long'),
  orgName: z.string().trim().min(2, 'Organization name too short').max(100, 'Organization name too long'),
  orgType: z.enum(['startup', 'enterprise', 'agency', 'consulting', 'nonprofit', 'education']),
  orgDescription: z.string().trim().max(1000).optional().default(''),
  // Optional for dev/automation: allow client_id override
  client_id: z.string().trim().min(1).optional(),
});

// Resolve client id from JWT, API key, dev header, or payload override
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev-only-secret' : undefined as any);
const resolveClientId: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers['authorization'];
    const raw = Array.isArray(authHeader) ? authHeader[0] : authHeader;

    if (raw) {
      let token = raw.startsWith('Bearer ') ? raw.slice(7) : raw;
      if (token.startsWith('sk-')) {
        return authenticateApiKey(req, res, next);
      }
      if (!JWT_SECRET) return res.status(401).json({ error: 'Server auth not configured' });
      try {
        const decoded: any = jwt.verify(token, JWT_SECRET);
        // Prefer resolving client_id by email from profiles for consistency
        const email: string | undefined = (decoded?.email || decoded?.email_address || (Array.isArray(decoded?.email_addresses) ? decoded.email_addresses[0]?.email_address : undefined));
        if (email && typeof email === 'string') {
          const { data: prof } = await supabase
            .from('profiles')
            .select('client_id')
            .eq('email', email.toLowerCase())
            .maybeSingle();
          if (prof?.client_id) {
            (req as AuthenticatedRequest).clientId = prof.client_id;
            return next();
          }
        }
        // Fallback to embedded clientId if present
        const cid = decoded?.clientId;
        if (cid && typeof cid === 'string' && cid.trim().length > 0) {
          (req as AuthenticatedRequest).clientId = cid;
          return next();
        }
      } catch {}
    }

    // Dev overrides
    if (process.env.NODE_ENV !== 'production') {
      const cidHeader = (req.headers['x-client-id'] as string | undefined)?.trim();
      if (cidHeader) {
        (req as AuthenticatedRequest).clientId = cidHeader;
        return next();
      }
      const bodyCid = (req.body as any)?.client_id as string | undefined;
      if (bodyCid && bodyCid.trim().length > 0) {
        (req as AuthenticatedRequest).clientId = bodyCid.trim();
        return next();
      }
    }

    // No identity resolved; continue (handler may generate a new client id for first-time users)
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

const createOrganizationSimple: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = simpleOrgSchema.safeParse(req.body || {});
    if (!result.success) {
      return res.status(400).json({ success: false, error: 'Validation Error', details: result.error.issues });
    }
    const { orgName, orgType, orgDescription, email } = result.data;

    const authReq = req as AuthenticatedRequest;
    let clientId = authReq.clientId;
    if (!clientId || clientId.trim().length === 0) {
      // Try to resolve by email from profiles
      const normalizedEmail = String(email).toLowerCase();
      const { data: prof } = await supabase
        .from('profiles')
        .select('client_id')
        .eq('email', normalizedEmail)
        .maybeSingle();
      clientId = prof?.client_id || undefined;
      if (!clientId) {
        // First-time: generate a new client id
        clientId = await generateShortClientId();
      }
    }

    // Duplicate name guard per client
    const { count: existingCount, error: dupErr } = await supabase
      .from('organizations')
      .select('id', { count: 'exact', head: true })
      .eq('client_id', clientId)
      .eq('name', orgName);
    if (dupErr) throw dupErr;
    if ((existingCount || 0) > 0) {
      return res.status(409).json({ success: false, error: 'Organization name already exists' });
    }

    const { data: organization, error: orgErr } = await supabase
      .from('organizations')
      .insert(addTraceContext({
        name: orgName,
        plan: orgType,
        client_id: clientId,
        description: orgDescription,
      }, req as any))
      .select()
      .single();
    if (orgErr) throw orgErr;

    // Ensure a matching profile exists for this client to satisfy api_keys FK
    const normalizedEmail = String(email).toLowerCase();
    const fallbackName = normalizedEmail.split('@')[0] || 'User';
    const { data: existingProfile } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', normalizedEmail)
      .maybeSingle();
    if (existingProfile) {
      if (!existingProfile.client_id || existingProfile.client_id !== clientId) {
        await supabase
          .from('profiles')
          .update({ client_id: clientId })
          .eq('id', existingProfile.id);
      }
    } else {
      await supabase
        .from('profiles')
        .insert({ email: normalizedEmail, full_name: fallbackName, role: 'owner', client_id: clientId });
    }

    return res.status(201).json({ success: true, data: { client_id: clientId, organization } });
  } catch (error) {
    return next(error);
  }
};

// Apply client resolver for setup organization; allow both JWT/API key or dev overrides
router.post('/organization', resolveClientId, createOrganizationSimple);

export default router; 
