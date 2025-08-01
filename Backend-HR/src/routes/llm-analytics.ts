import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import { authenticateApiKey, AuthenticatedRequest, requirePermission } from '../middleware/auth';
import { calculateTokenCost, LLM_PRICING } from '../config/llm-pricing';

const router = Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// GET /llm-usage/aggregated
router.get('/aggregated',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { 
        timeframe = '24h', 
        start_date,
        end_date 
      } = req.query;

      // Calculate date range
      let startDate: Date;
      const endDate = end_date ? new Date(end_date as string) : new Date();

      if (start_date) {
        startDate = new Date(start_date as string);
      } else {
        switch (timeframe) {
          case '1h':
            startDate = new Date(Date.now() - 60 * 60 * 1000);
            break;
          case '24h':
            startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
            break;
          case '7d':
            startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            break;
          case '30d':
            startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
            break;
          default:
            startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
        }
      }

      // Get LLM usage data
      const { data: llmUsageData, error: llmError } = await supabase
        .from('llm_usage')
        .select('provider, model, tokens_input, tokens_output, metadata, timestamp')
        .eq('client_id', req.clientId)
        .gte('timestamp', startDate.toISOString())
        .lte('timestamp', endDate.toISOString())
        .order('timestamp', { ascending: false });

      if (llmError) {
        throw llmError;
      }

      // Aggregate data by provider and model
      const aggregatedData: any = {};
      let totalCost = 0;
      let totalInputTokens = 0;
      let totalOutputTokens = 0;

      for (const usage of llmUsageData || []) {
        const { provider, model, tokens_input, tokens_output, metadata } = usage;
        
        // Calculate cost if not already in metadata
        let cost = metadata?.cost_usd || 0;
        if (!cost) {
          cost = calculateTokenCost(provider, model, tokens_input, tokens_output);
        }

        // Initialize provider if not exists
        if (!aggregatedData[provider]) {
          aggregatedData[provider] = {};
        }

        // Initialize model if not exists
        if (!aggregatedData[provider][model]) {
          aggregatedData[provider][model] = {
            input_tokens: 0,
            output_tokens: 0,
            cost: 0,
            request_count: 0
          };
        }

        // Aggregate values
        aggregatedData[provider][model].input_tokens += tokens_input;
        aggregatedData[provider][model].output_tokens += tokens_output;
        aggregatedData[provider][model].cost += cost;
        aggregatedData[provider][model].request_count += 1;

        // Global totals
        totalCost += cost;
        totalInputTokens += tokens_input;
        totalOutputTokens += tokens_output;
      }

      // Calculate provider-level totals
      const providerTotals: any = {};
      for (const provider in aggregatedData) {
        providerTotals[provider] = {
          input_tokens: 0,
          output_tokens: 0,
          cost: 0,
          request_count: 0,
          models: Object.keys(aggregatedData[provider]).length
        };

        for (const model in aggregatedData[provider]) {
          const modelData = aggregatedData[provider][model];
          providerTotals[provider].input_tokens += modelData.input_tokens;
          providerTotals[provider].output_tokens += modelData.output_tokens;
          providerTotals[provider].cost += modelData.cost;
          providerTotals[provider].request_count += modelData.request_count;
        }
      }

      // Round costs to 4 decimal places
      for (const provider in aggregatedData) {
        for (const model in aggregatedData[provider]) {
          aggregatedData[provider][model].cost = Math.round(aggregatedData[provider][model].cost * 10000) / 10000;
        }
        providerTotals[provider].cost = Math.round(providerTotals[provider].cost * 10000) / 10000;
      }

      const response = {
        timeframe: {
          start: startDate.toISOString(),
          end: endDate.toISOString(),
          requested_timeframe: timeframe
        },
        summary: {
          total_cost: Math.round(totalCost * 10000) / 10000,
          total_input_tokens: totalInputTokens,
          total_output_tokens: totalOutputTokens,
          total_requests: llmUsageData?.length || 0,
          providers_used: Object.keys(aggregatedData).length
        },
        by_provider: providerTotals,
        detailed: aggregatedData,
        last_updated: new Date().toISOString()
      };

      logger.info('LLM usage aggregation requested', {
        client_id: req.clientId,
        timeframe,
        total_cost: response.summary.total_cost,
        total_requests: response.summary.total_requests
      });

      res.json(response);
    } catch (error: any) {
      logger.error('LLM usage aggregation error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// GET /llm-usage/top-models
router.get('/top-models',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { limit = 10, sort_by = 'cost' } = req.query;
      const limitNum = parseInt(limit as string, 10);

      // Calculate date range
      const endDate = new Date();
      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // Last 24 hours

      // Get usage data for ranking
      const { data: llmUsageData, error } = await supabase
        .from('llm_usage')
        .select('provider, model, tokens_input, tokens_output, metadata')
        .eq('client_id', req.clientId)
        .gte('timestamp', startDate.toISOString())
        .lte('timestamp', endDate.toISOString());

      if (error) {
        throw error;
      }

      // Aggregate by model
      const modelStats: any = {};
      
      for (const usage of llmUsageData || []) {
        const { provider, model, tokens_input, tokens_output, metadata } = usage;
        const key = `${provider}/${model}`;
        
        let cost = metadata?.cost_usd || 0;
        if (!cost) {
          cost = calculateTokenCost(provider, model, tokens_input, tokens_output);
        }

        if (!modelStats[key]) {
          modelStats[key] = {
            provider,
            model,
            input_tokens: 0,
            output_tokens: 0,
            cost: 0,
            request_count: 0
          };
        }

        modelStats[key].input_tokens += tokens_input;
        modelStats[key].output_tokens += tokens_output;
        modelStats[key].cost += cost;
        modelStats[key].request_count += 1;
      }

      // Convert to array and sort
      let topModels = Object.values(modelStats);
      
      switch (sort_by) {
        case 'cost':
          topModels.sort((a: any, b: any) => b.cost - a.cost);
          break;
        case 'tokens':
          topModels.sort((a: any, b: any) => (b.input_tokens + b.output_tokens) - (a.input_tokens + a.output_tokens));
          break;
        case 'requests':
          topModels.sort((a: any, b: any) => b.request_count - a.request_count);
          break;
        default:
          topModels.sort((a: any, b: any) => b.cost - a.cost);
      }

      // Limit results and round costs
      topModels = topModels.slice(0, limitNum).map((model: any) => ({
        ...model,
        cost: Math.round(model.cost * 10000) / 10000
      }));

      res.json({
        top_models: topModels,
        sort_by,
        limit: limitNum,
        total_models: Object.keys(modelStats).length,
        last_updated: new Date().toISOString()
      });
    } catch (error: any) {
      logger.error('Top models error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

// GET /llm-usage/pricing-info
router.get('/pricing-info',
  requirePermission('read'),
  async (req: AuthenticatedRequest, res) => {
    try {
      res.json({
        pricing_data: LLM_PRICING,
        supported_providers: Object.keys(LLM_PRICING),
        last_updated: new Date().toISOString(),
        note: "Prices are per 1,000 tokens"
      });
    } catch (error: any) {
      logger.error('Pricing info error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: error.message
      });
    }
  }
);

export { router as llmAnalyticsRoutes }; 