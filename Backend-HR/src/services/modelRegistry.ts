import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';

/**
 * Record usage for unknown provider/model combinations.
 * Creates a new row if it does not exist and aggregates token counts.
 */
export async function recordUnknownModel(
  provider: string,
  model: string,
  inputTokens: number,
  outputTokens: number
): Promise<void> {
  try {
    const providerKey = provider.toLowerCase();
    const modelKey = model.toLowerCase();

    const { data, error } = await supabase
      .from('unknown_llm_models')
      .select('input_tokens, output_tokens')
      .eq('provider', providerKey)
      .eq('model', modelKey)
      .maybeSingle();

    if (error) {
      logger.error('Failed to check unknown model:', error.message);
      return;
    }

    if (!data) {
      const { error: insertError } = await supabase
        .from('unknown_llm_models')
        .insert({
          provider: providerKey,
          model: modelKey,
          input_tokens: inputTokens,
          output_tokens: outputTokens
        });
      if (insertError) {
        logger.error('Failed to insert unknown model:', insertError.message);
      }
    } else {
      const { error: updateError } = await supabase
        .from('unknown_llm_models')
        .update({
          input_tokens: (data.input_tokens || 0) + inputTokens,
          output_tokens: (data.output_tokens || 0) + outputTokens
        })
        .eq('provider', providerKey)
        .eq('model', modelKey);
      if (updateError) {
        logger.error('Failed to update unknown model:', updateError.message);
      }
    }
  } catch (err: any) {
    logger.error('Error recording unknown model:', err.message || err);
  }
}
