import express from 'express';
import { supabase } from '../lib/supabase';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// GET /metrics/overview
router.get('/overview', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    // Get success rates from view
    const { data: successData, error: successError } = await supabase
      .from('view_success_rate')
      .select('*');

    if (successError) {
      logger.error('Failed to get success rates', { error: successError });
      throw successError;
    }

    // Get response times from view
    const { data: responseData, error: responseError } = await supabase
      .from('view_avg_response_time')
      .select('*');

    if (responseError) {
      logger.error('Failed to get response times', { error: responseError });
      throw responseError;
    }

    // Get quality metrics from view
    const { data: qualityData, error: qualityError } = await supabase
      .from('view_quality_metrics')
      .select('*');

    if (qualityError) {
      logger.error('Failed to get quality metrics', { error: qualityError });
      throw qualityError;
    }

    // Combine data by agent_id
    const agentMetrics = (successData || []).map(agent => {
      const responseMetrics = responseData?.find(r => r.agent_id === agent.agent_id);
      const qualityMetrics = qualityData?.find(q => q.agent_id === agent.agent_id);

      return {
        agent_id: agent.agent_id,
        total_sessions: agent.total_sessions,
        successful_sessions: agent.successful_sessions,
        failed_sessions: agent.failed_sessions,
        success_rate_percent: agent.success_rate_percent,
        avg_response_time_ms: responseMetrics?.avg_response_time_ms || null,
        avg_quality_score: qualityMetrics?.avg_quality_score || null,
        last_updated: agent.last_updated
      };
    });

    res.json({ success: true, data: agentMetrics });
  } catch (error: any) {
    logger.error('Failed to get metrics overview', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /metrics/success-rates
router.get('/success-rates', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('view_success_rate')
      .select('*')
      .order('success_rate_percent', { ascending: false });

    if (error) {
      logger.error('Failed to get success rates', { error });
      throw error;
    }

    res.json({ success: true, data: data || [] });
  } catch (error: any) {
    logger.error('Failed to get success rates', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /metrics/response-times
router.get('/response-times', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('view_avg_response_time')
      .select('*')
      .order('avg_response_time_ms', { ascending: true });

    if (error) {
      logger.error('Failed to get response times', { error });
      throw error;
    }

    res.json({ success: true, data: data || [] });
  } catch (error: any) {
    logger.error('Failed to get response times', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /metrics/quality
router.get('/quality', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('view_quality_metrics')
      .select('*')
      .order('avg_quality_score', { ascending: false });

    if (error) {
      logger.error('Failed to get quality metrics', { error });
      throw error;
    }

    res.json({ success: true, data: data || [] });
  } catch (error: any) {
    logger.error('Failed to get quality metrics', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router; 