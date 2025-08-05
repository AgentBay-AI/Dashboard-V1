import { Router, Response, Request, RequestHandler } from 'express';
import { supabase } from '../lib/supabase';
import { z } from 'zod';
import { validateSchema } from '../middleware/validation';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

const organizationSchema = z.object({
  orgName: z.string(),
  orgType: z.string(),
  orgDescription: z.string(),
  email: z.string().email(),
});

type OrganizationBody = z.infer<typeof organizationSchema>;

// Create organization
const createOrganization: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const { orgName, orgType, orgDescription, email } = req.body as OrganizationBody;

    const { data, error } = await supabase
      .from('organizations')
      .insert(addTraceContext({
        name: orgName,
        plan: orgType === 'enterprise' ? 'Enterprise' : 
              orgType === 'startup' ? 'Basic' : 'Professional',
        client_id: authReq.clientId,
        metadata: {
          description: orgDescription,
          email: email,
          type: orgType
        }
      }, authReq))
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      data
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Get organizations for client
const getOrganizations: RequestHandler = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  try {
    const { data: organizations, error } = await supabase
      .from('view_organization_metrics')
      .select('*')
      .eq('client_id', authReq.clientId);

    if (error) throw error;

    res.json({
      success: true,
      data: organizations
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

router.post('/', requirePermission('write'), validateSchema(organizationSchema), createOrganization);
router.get('/', requirePermission('read'), getOrganizations);

export default router; 