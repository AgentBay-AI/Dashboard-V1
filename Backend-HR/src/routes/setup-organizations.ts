import { Router, Response, Request, RequestHandler, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { requirePermission, AuthenticatedRequest } from '../middleware/auth';

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

export default router; 
