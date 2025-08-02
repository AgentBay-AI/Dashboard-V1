import { z } from 'zod';

// Agent schemas
export const agentRegisterSchema = z.object({
    agent_id: z.string(),
    client_id: z.string(),
    registration_time: z.string(),
    status: z.string(),
    sdk_version: z.string(),
    metadata: z.record(z.any()).optional()
});

export const agentStatusSchema = z.object({
    agent_id: z.string(),
    client_id: z.string(),
    status: z.enum(['active', 'idle', 'busy', 'error']),
    timestamp: z.string(),
    metadata: z.record(z.any()).optional()
});

export const agentActivitySchema = z.object({
    agent_id: z.string(),
    client_id: z.string(),
    activity_type: z.string(),
    timestamp: z.string(),
    details: z.record(z.any()).optional(),
    duration: z.number().optional(),
    metadata: z.record(z.any()).optional()
});

// LLM usage schema
export const llmUsageSchema = z.object({
    agent_id: z.string(),
    client_id: z.string(),
    session_id: z.string(),
    timestamp: z.string(),
    provider: z.string(),
    model: z.string(),
    tokens_input: z.number().int(),
    tokens_output: z.number().int(),
    metadata: z.record(z.any()).optional()
});

// Security metrics schema
export const securityMetricsSchema = z.object({
    agent_id: z.string(),
    client_id: z.string(),
    event_type: z.string(),
    severity: z.enum(['low', 'medium', 'high']).optional(),
    metadata: z.record(z.any()).optional()
}); 