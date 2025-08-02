import express from 'express';
import { authenticateApiKey, requirePermission, AuthenticatedRequest } from '../middleware/auth';
import { validateSchema } from '../middleware/validation';
import { 
    agentRegisterSchema,
    agentStatusSchema,
    agentActivitySchema,
    llmUsageSchema,
    securityMetricsSchema
} from '../lib/schemas';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { addTraceContext } from '../middleware/tracing';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get active agents
router.get('/active',
    requirePermission('read'),
    async (req: AuthenticatedRequest, res) => {
        try {
            // Get active agents
            const { data: activeAgents, error: agentsError } = await supabase
                .from('agents')
                .select('*')
                .eq('client_id', req.clientId)
                .eq('status', 'active')
                .order('registration_time', { ascending: false });

            if (agentsError) throw agentsError;

            res.json({
                success: true,
                data: activeAgents || []
            });
        } catch (error: any) {
            logger.error('Active agents fetch error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to fetch active agents',
                message: error.message
            });
        }
    }
);

// Get operations overview
router.get('/operations/overview',
    requirePermission('read'),
    async (req: AuthenticatedRequest, res) => {
        try {
            // Get active agents
            const { data: activeAgents, error: agentsError } = await supabase
                .from('agents')
                .select('*')
                .eq('client_id', req.clientId)
                .order('registration_time', { ascending: false });

            if (agentsError) throw agentsError;

            // Get recent activity
            const { data: recentActivity, error: activityError } = await supabase
                .from('agent_activity')
                .select('*')
                .eq('client_id', req.clientId)
                .order('timestamp', { ascending: false })
                .limit(10);

            if (activityError) throw activityError;

            // Calculate status distribution
            const statusDistribution = (activeAgents || []).reduce((acc: Record<string, number>, agent: any) => {
                acc[agent.status] = (acc[agent.status] || 0) + 1;
                return acc;
            }, {});

            res.json({
                success: true,
                data: {
                    active_agents: activeAgents || [],
                    status_distribution: statusDistribution,
                    recent_activity: recentActivity || []
                }
            });
        } catch (error: any) {
            logger.error('Operations overview error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to fetch operations overview',
                message: error.message
            });
        }
    }
);

// Agent registration
router.post('/register', 
    validateSchema(agentRegisterSchema),
    async (req, res) => {
        try {
            const data = addTraceContext(req.body, req);
            
            const { error } = await supabase
                .from('agents')
                .insert(data);

            if (error) {
                logger.error('Agent registration failed:', error);
                return res.status(500).json({
                    error: 'Registration failed',
                    message: error.message
                });
            }

            res.status(201).json({
                message: 'Agent registered successfully',
                agent_id: data.agent_id
            });
        } catch (error: any) {
            logger.error('Agent registration error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// Agent status update
router.post('/status',
    validateSchema(agentStatusSchema),
    async (req, res) => {
        try {
            const data = addTraceContext(req.body, req);
            
            const { error } = await supabase
                .from('agent_status')
                .insert(data);

            if (error) {
                logger.error('Status update failed:', error);
                return res.status(500).json({
                    error: 'Status update failed',
                    message: error.message
                });
            }

            res.status(200).json({
                message: 'Status updated successfully'
            });
        } catch (error: any) {
            logger.error('Status update error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// Agent activity logging
router.post('/activity',
    validateSchema(agentActivitySchema),
    async (req, res) => {
        try {
            const data = addTraceContext(req.body, req);
            
            const { error } = await supabase
                .from('agent_activity')
                .insert(data);

            if (error) {
                logger.error('Activity logging failed:', error);
                return res.status(500).json({
                    error: 'Activity logging failed',
                    message: error.message
                });
            }

            res.status(200).json({
                message: 'Activity logged successfully'
            });
        } catch (error: any) {
            logger.error('Activity logging error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// LLM usage tracking
router.post('/llm-usage',
    validateSchema(llmUsageSchema),
    async (req, res) => {
        try {
            const data = addTraceContext(req.body, req);
            
            const { error } = await supabase
                .from('llm_usage')
                .insert(data);

            if (error) {
                logger.error('LLM usage tracking failed:', error);
                return res.status(500).json({
                    error: 'Usage tracking failed',
                    message: error.message
                });
            }

            res.status(200).json({
                message: 'LLM usage tracked successfully'
            });
        } catch (error: any) {
            logger.error('LLM usage tracking error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// Security metrics reporting
router.post('/security',
    validateSchema(securityMetricsSchema),
    async (req, res) => {
        try {
            const data = addTraceContext(req.body, req);
            
            const { error } = await supabase
                .from('security_events')
                .insert(data);

            if (error) {
                logger.error('Security metrics reporting failed:', error);
                return res.status(500).json({
                    error: 'Metrics reporting failed',
                    message: error.message
                });
            }

            res.status(200).json({
                message: 'Security metrics reported successfully'
            });
        } catch (error: any) {
            logger.error('Security metrics reporting error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

export default router; 