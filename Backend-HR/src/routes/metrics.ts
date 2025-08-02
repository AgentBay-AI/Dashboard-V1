import express from 'express';
import { authenticateApiKey, requirePermission } from '../middleware/auth';
import { validateSchema } from '../middleware/validation';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { addTraceContext } from '../middleware/tracing';
import { AuthenticatedRequest } from '../middleware/auth';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// Get metrics overview
router.get('/overview', async (req: AuthenticatedRequest, res) => {
    try {
        const { data: successRates, error: successError } = await supabase
            .from('view_success_rate')
            .select('*')
            .eq('client_id', req.clientId);

        if (successError) {
            logger.error('Failed to get success rates:', successError);
            return res.status(500).json({
                error: 'Query failed',
                message: successError.message
            });
        }

        const { data: responseTimes, error: responseError } = await supabase
            .from('view_avg_response_time')
            .select('*')
            .eq('client_id', req.clientId);

        if (responseError) {
            logger.error('Failed to get response times:', responseError);
            return res.status(500).json({
                error: 'Query failed',
                message: responseError.message
            });
        }

        const { data: qualityMetrics, error: qualityError } = await supabase
            .from('view_quality_metrics')
            .select('*')
            .eq('client_id', req.clientId);

        if (qualityError) {
            logger.error('Failed to get quality metrics:', qualityError);
            return res.status(500).json({
                error: 'Query failed',
                message: qualityError.message
            });
        }

        // Combine metrics by agent_id
        const metrics = successRates?.map(success => {
            const responseTime = responseTimes?.find(rt => rt.agent_id === success.agent_id);
            const quality = qualityMetrics?.find(qm => qm.agent_id === success.agent_id);

            return {
                agent_id: success.agent_id,
                total_sessions: success.total_sessions,
                successful_sessions: success.successful_sessions,
                failed_sessions: success.failed_sessions,
                success_rate_percent: success.success_rate_percent,
                avg_response_time_ms: responseTime?.avg_response_time_ms,
                min_response_time_ms: responseTime?.min_response_time_ms,
                max_response_time_ms: responseTime?.max_response_time_ms,
                avg_quality_score: quality?.avg_quality_score,
                rated_sessions: quality?.rated_sessions
            };
        });

        res.json(metrics);
    } catch (error: any) {
        logger.error('Metrics overview error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Get success rates
router.get('/success-rates', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('view_success_rate')
            .select('*');

        if (error) {
            logger.error('Failed to get success rates:', error);
            return res.status(500).json({
                error: 'Query failed',
                message: error.message
            });
        }

        res.json(data);
    } catch (error: any) {
        logger.error('Success rates query error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Get response times
router.get('/response-times', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('view_avg_response_time')
            .select('*');

        if (error) {
            logger.error('Failed to get response times:', error);
            return res.status(500).json({
                error: 'Query failed',
                message: error.message
            });
        }

        res.json(data);
    } catch (error: any) {
        logger.error('Response times query error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Get quality metrics
router.get('/quality', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('view_quality_metrics')
            .select('*');

        if (error) {
            logger.error('Failed to get quality metrics:', error);
            return res.status(500).json({
                error: 'Query failed',
                message: error.message
            });
        }

        res.json(data);
    } catch (error: any) {
        logger.error('Quality metrics query error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

export default router; 