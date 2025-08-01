import { z } from 'zod';

// Common schemas
const timestampSchema = z.string().datetime();
const clientIdSchema = z.string().min(1);
const agentIdSchema = z.string().min(1);
const sessionIdSchema = z.string().min(1);

// Agent Operations Schemas
export const agentRegisterSchema = z.object({
  agent_id: agentIdSchema,
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  metadata: z.object({
    version: z.string().optional(),
    environment: z.enum(['development', 'staging', 'production']).optional(),
    capabilities: z.array(z.string()).optional()
  }).optional()
});

export const agentStatusSchema = z.object({
  agent_id: agentIdSchema,
  status: z.enum(['active', 'idle', 'error', 'maintenance']),
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  metadata: z.object({
    cpu_usage: z.number().min(0).max(100).optional(),
    memory_usage: z.number().min(0).optional(),
    last_activity: timestampSchema.optional()
  }).optional()
});

// Conversation Schemas
export const conversationStartSchema = z.object({
  session_id: sessionIdSchema,
  agent_id: agentIdSchema,
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  run_id: z.string().optional(),
  user_id: z.string().optional(),
  metadata: z.object({
    conversation_type: z.string().optional(),
    channel: z.string().optional(),
    priority: z.enum(['low', 'normal', 'high', 'critical']).optional()
  }).optional(),
  security_flags: z.object({
    tamper_detected: z.boolean().optional(),
    pii_detected: z.boolean().optional(),
    compliance_violation: z.boolean().optional()
  }).optional()
});

export const conversationEndSchema = z.object({
  session_id: sessionIdSchema,
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  outcome: z.enum(['resolved', 'escalated', 'failed', 'timeout']).optional(),
  quality_score: z.enum(['poor', 'fair', 'good', 'excellent']).optional(),
  response_time_ms: z.number().min(0).optional(),
  user_satisfaction: z.number().min(0).max(5).optional(),
  metadata: z.object({
    resolution_steps: z.number().optional(),
    escalation_reason: z.string().optional(),
    final_status: z.string().optional()
  }).optional(),
  security_flags: z.object({
    tamper_detected: z.boolean().optional(),
    pii_detected: z.boolean().optional(),
    compliance_violation: z.boolean().optional()
  }).optional()
});

export const conversationResumeSchema = z.object({
  session_id: sessionIdSchema,
  agent_id: agentIdSchema,
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  resume_reason: z.string()
});

export const conversationLocalExpiredSchema = z.object({
  expired_sessions: z.array(z.object({
    session_id: sessionIdSchema,
    agent_id: agentIdSchema,
    start_time: timestampSchema,
    last_activity: timestampSchema,
    expiry_reason: z.string()
  })),
  timestamp: timestampSchema,
  client_id: clientIdSchema
});

export const failedSessionSchema = z.object({
  session_id: sessionIdSchema,
  agent_id: z.string().optional(),
  timestamp: timestampSchema,
  client_id: clientIdSchema,
  failure_reason: z.string(),
  error_details: z.object({
    error_code: z.string().optional(),
    error_message: z.string().optional(),
    stack_trace: z.string().optional()
  }).optional()
});

// Security Schemas
export const securityMetricsSchema = z.object({
  event_type: z.enum(['unclosed_sessions', 'pii_detected', 'compliance_violation']),
  timestamp: timestampSchema,
  agent_id: agentIdSchema.optional(),
  client_id: clientIdSchema,
  unclosed_count: z.number().min(0).optional(),
  unclosed_sessions: z.array(z.object({
    session_id: sessionIdSchema,
    agent_id: agentIdSchema,
    start_time: timestampSchema,
    last_activity: timestampSchema,
    duration_minutes: z.number().min(0).optional(),
    risk_level: z.enum(['low', 'medium', 'high', 'critical']).optional()
  })).optional(),
  metadata: z.object({
    detection_method: z.string().optional(),
    threshold_exceeded: z.boolean().optional(),
    total_sessions_tracked: z.number().min(0).optional()
  }).optional()
});

export const securityTamperSchema = z.object({
  event_type: z.literal('tamper_detected'),
  timestamp: timestampSchema,
  agent_id: agentIdSchema.optional(),
  client_id: clientIdSchema,
  sdk_version: z.string(),
  checksum_expected: z.string(),
  checksum_actual: z.string(),
  modified_files: z.array(z.string()),
  severity: z.enum(['low', 'medium', 'high', 'critical'])
});

// LLM Usage Schema
export const llmUsageSchema = z.object({
  timestamp: timestampSchema,
  agent_id: agentIdSchema,
  provider: z.enum(['openai', 'claude', 'anthropic', 'gemini', 'google']),
  model: z.string(),
  tokens_input: z.number().min(0),
  tokens_output: z.number().min(0),
  session_id: sessionIdSchema.optional(),
  client_id: clientIdSchema,
  metadata: z.object({
    request_id: z.string().optional(),
    user_id: z.string().optional(),
    conversation_turn: z.number().optional()
  }).optional()
});

// Compliance Schemas
export const complianceAuditSchema = z.object({
  audit_entry: z.object({
    session_id: sessionIdSchema,
    timestamp: timestampSchema,
    event_type: z.string(),
    compliance_flags: z.object({
      gdpr_scope: z.boolean().optional(),
      hipaa_scope: z.boolean().optional(),
      pii_detected: z.boolean().optional(),
      phi_detected: z.boolean().optional(),
      cross_border_transfer: z.boolean().optional()
    }).optional(),
    policy_violations: z.array(z.string()).optional(),
    data_sent_to: z.string().optional(),
    retention_policy: z.string().optional(),
    user_acknowledged: z.boolean().optional()
  }),
  hash_chain: z.string().optional(),
  current_hash: z.string(),
  client_id: clientIdSchema.optional()
});

export const complianceAcknowledgmentSchema = z.object({
  session_id: sessionIdSchema,
  policy_type: z.string(),
  acknowledged_by: z.string(),
  acknowledgment_reason: z.string(),
  timestamp: timestampSchema,
  client_id: clientIdSchema.optional()
});

// API Key Management Schema
export const createApiKeySchema = z.object({
  client_id: z.string().min(1),
  client_name: z.string().optional(),
  permissions: z.array(z.string()).default(['read', 'write']),
  rate_limit_per_minute: z.number().min(1).max(10000).default(1000),
  expires_at: timestampSchema.optional()
});

// Type exports for TypeScript
export type AgentRegister = z.infer<typeof agentRegisterSchema>;
export type AgentStatus = z.infer<typeof agentStatusSchema>;
export type ConversationStart = z.infer<typeof conversationStartSchema>;
export type ConversationEnd = z.infer<typeof conversationEndSchema>;
export type ConversationResume = z.infer<typeof conversationResumeSchema>;
export type ConversationLocalExpired = z.infer<typeof conversationLocalExpiredSchema>;
export type FailedSession = z.infer<typeof failedSessionSchema>;
export type SecurityMetrics = z.infer<typeof securityMetricsSchema>;
export type SecurityTamper = z.infer<typeof securityTamperSchema>;
export type LLMUsage = z.infer<typeof llmUsageSchema>;
export type ComplianceAudit = z.infer<typeof complianceAuditSchema>;
export type ComplianceAcknowledgment = z.infer<typeof complianceAcknowledgmentSchema>;
export type CreateApiKey = z.infer<typeof createApiKeySchema>; 