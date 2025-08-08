/**
 * LLM Pricing Configuration
 * Prices are per 1,000 tokens (input/output)
 * Updated: August 2025
 */

export interface ModelPricing {
  input: number;  // Price per 1K input tokens
  output: number; // Price per 1K output tokens
}

export interface ProviderPricing {
  [model: string]: ModelPricing;
}

export interface LLMPricingConfig {
  [provider: string]: ProviderPricing;
}

export const LLM_PRICING: LLMPricingConfig = {
  openai: {
    // 2025 series
    'gpt-4o': { input: 0.005, output: 0.015 },             // $5 / $15 per 1M
    'gpt-4o-mini': { input: 0.00015, output: 0.0006 },     // $0.15 / $0.60 per 1M
    'gpt-4.1': { input: 0.002, output: 0.008 },            // $2 / $8 per 1M
    'gpt-4.1-mini': { input: 0.0004, output: 0.0016 },     // $0.40 / $1.60 per 1M
    'gpt-4.1-nano': { input: 0.0001, output: 0.0004 },     // $0.10 / $0.40 per 1M
    'o3': { input: 0.001, output: 0.004 },                 // $1 / $4 per 1M
    'o4-mini': { input: 0.0006, output: 0.0024 },          // $0.60 / $2.40 per 1M

    // GPT-5 placeholders (align to 4.1 tiers until official rates are confirmed)
    'gpt-5': { input: 0.002, output: 0.008 },
    'gpt-5-mini': { input: 0.0004, output: 0.0016 },

    // Legacy carried forward
    'gpt-4o-mini-2024-07-18': { input: 0.00015, output: 0.0006 },
    'gpt-4-turbo': { input: 0.01, output: 0.03 },
    'gpt-4': { input: 0.03, output: 0.06 },
    'gpt-3.5-turbo': { input: 0.0015, output: 0.002 },
    'gpt-3.5-turbo-0125': { input: 0.0005, output: 0.0015 },
    'text-embedding-3-small': { input: 0.00002, output: 0 },
    'text-embedding-3-large': { input: 0.00013, output: 0 }
  },
  anthropic: {
    // Claude 4 family
    'claude-4-opus': { input: 0.015, output: 0.075 },      // $15 / $75 per 1M
    'claude-4.1-opus': { input: 0.015, output: 0.075 },    // $15 / $75 per 1M
    'claude-4-sonnet': { input: 0.003, output: 0.015 },    // $3 / $15 per 1M

    // Newer
    'claude-3.7-sonnet': { input: 0.003, output: 0.015 },
    // Existing
    'claude-3.5-sonnet': { input: 0.003, output: 0.015 },
    'claude-3-opus': { input: 0.015, output: 0.075 },
    'claude-3-sonnet': { input: 0.003, output: 0.015 },
    'claude-3-haiku': { input: 0.00025, output: 0.00125 },
    'claude-2.1': { input: 0.008, output: 0.024 },
    'claude-2.0': { input: 0.008, output: 0.024 }
  },
  google: {
    // Gemini 2.x
    'gemini-2.5-pro': { input: 0.0025, output: 0.015 },    // $2.5 / $15 per 1M
    // Prior
    'gemini-1.5-pro': { input: 0.000125, output: 0.000375 },
    'gemini-1.5-flash': { input: 0.0000375, output: 0.00015 },
    'gemini-pro': { input: 0.0005, output: 0.0015 },
    'gemini-pro-vision': { input: 0.0005, output: 0.0015 }
  }
};

/**
 * Calculate cost for token usage
 */
export function calculateTokenCost(
  provider: string, 
  model: string, 
  inputTokens: number, 
  outputTokens: number
): number {
  const providerKey = provider.toLowerCase();
  const modelKey = model.toLowerCase();
  const providerPricing = LLM_PRICING[providerKey];
  if (!providerPricing) {
    console.warn(`Unknown provider: ${provider}`);
    return 0;
  }

  const modelPricing = providerPricing[modelKey];
  if (!modelPricing) {
    console.warn(`Unknown model: ${model} for provider: ${provider}`);
    return 0;
  }

  const inputCost = (inputTokens / 1000) * modelPricing.input;
  const outputCost = (outputTokens / 1000) * modelPricing.output;
  
  return inputCost + outputCost;
}

/**
 * Get all available providers
 */
export function getAvailableProviders(): string[] {
  return Object.keys(LLM_PRICING);
}

/**
 * Get available models for a provider
 */
export function getAvailableModels(provider: string): string[] {
  const providerPricing = LLM_PRICING[provider.toLowerCase()];
  return providerPricing ? Object.keys(providerPricing) : [];
}

/**
 * Get pricing for a specific provider/model
 */
export function getModelPricing(provider: string, model: string): ModelPricing | null {
  const providerPricing = LLM_PRICING[provider.toLowerCase()];
  if (!providerPricing) return null;
  
  return providerPricing[model.toLowerCase()] || null;
} 