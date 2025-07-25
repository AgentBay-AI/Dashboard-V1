import { Router, Request, Response } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';

const router = Router();

// GET /api/frontend/organizations - Get organizations (empty if no DB)
router.get('/organizations', async (req: Request, res: Response): Promise<void> => {
  try {
    const { data: orgs, error } = await supabase
      .from('organizations')
      .select('*')
      .order('created_at', { ascending: true });

    if (error) {
      logger.warn('Organizations fetch failed, returning empty data:', error.message);
      res.json({ organizations: [], source: 'empty' });
      return;
    }

    // Transform to frontend format
    const transformedOrgs = orgs?.map(org => ({
      id: org.id,
      name: org.name,
      industry: org.industry,
      createdAt: org.created_at,
      description: org.description
    })) || [];

    res.json({
      organizations: transformedOrgs,
      source: 'database'
    });

  } catch (error) {
    logger.error('Organizations endpoint error:', error);
    res.json({ organizations: [], source: 'empty' });
  }
});

// GET /api/frontend/agents - Get agents (empty if no DB)
router.get('/agents', async (req: Request, res: Response): Promise<void> => {
  try {
    const { organization_id } = req.query;

    let query = supabase
      .from('agents')
      .select('*');

    if (organization_id) {
      query = query.eq('organization_id', organization_id);
    }

    const { data: agents, error } = await query;

    if (error) {
      logger.warn('Agents fetch failed, returning empty data:', error.message);
      res.json({
        agents: [],
        total: 0,
        source: 'empty'
      });
      return;
    }

    // Transform database format to exact frontend format
    const transformedAgents = agents?.map(agent => ({
      id: agent.id,
      name: agent.name,
      description: agent.description,
      organizationId: agent.organization_id,
      provider: agent.provider,
      framework: agent.framework,
      model: agent.model,
      status: agent.status,
      lastSync: agent.last_activity || agent.updated_at,
      models: [agent.model],
      apiKey: "****", // Always masked
      agentType: agent.agent_type,
      createdAt: agent.created_at,
      performance: 0, // Real performance from metrics table
      cost: 0, // Real cost from metrics table
      requests: 0, // Real requests from metrics table
      endpoint: agent.endpoint,
      noCodePlatform: agent.agent_type === 'nocode' ? 'zapier' : undefined
    })) || [];

    res.json({
      agents: transformedAgents,
      total: transformedAgents.length,
      source: 'database'
    });

  } catch (error) {
    logger.error('Frontend agents endpoint error:', error);
    res.json({
      agents: [],
      total: 0,
      source: 'empty'
    });
  }
});

export { router as frontendApiRoutes }; 