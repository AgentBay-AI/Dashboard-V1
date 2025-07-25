import { Router, Request, Response, NextFunction } from 'express'
import rateLimit from 'express-rate-limit'
import { supabase } from '../lib/supabase'
import { z } from 'zod'

// Extend Request interface to include agent property
interface AuthenticatedRequest extends Request {
  agent?: {
    id: string
    status: string
    organization_id: string
  }
}

const router = Router()

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
})

// Validation schemas
const MetricsSchema = z.object({
  agent_id: z.string().uuid(),
  type: z.literal('request'),
  timestamp: z.number().optional(),
  data: z.object({
    prompt_tokens: z.number().min(0),
    completion_tokens: z.number().min(0),
    cost: z.number().min(0),
    latency: z.number().min(0),
    model: z.string().optional(),
    provider: z.string().optional(),
    success: z.boolean().default(true),
    operation: z.string().optional(),
    metadata: z.record(z.any()).optional()
  })
})

const HealthSchema = z.object({
  agent_id: z.string().uuid(),
  type: z.literal('health'),
  timestamp: z.number().optional(),
  data: z.object({
    status: z.enum(['healthy', 'degraded', 'unhealthy', 'offline']),
    uptime: z.number().min(0).optional(),
    memory_usage: z.number().min(0).optional(),
    cpu_usage: z.number().min(0).max(100).optional(),
    response_time: z.number().min(0).optional(),
    error_count: z.number().min(0).optional(),
    last_error: z.string().optional(),
    metadata: z.record(z.any()).optional()
  })
})

const ErrorSchema = z.object({
  agent_id: z.string().uuid(),
  type: z.literal('error'),
  timestamp: z.number().optional(),
  data: z.object({
    error: z.string(),
    latency: z.number().min(0).optional(),
    operation: z.string().optional(),
    stack_trace: z.string().optional(),
    metadata: z.record(z.any()).optional()
  })
})

const SecurityEventSchema = z.object({
  agent_id: z.string().uuid(),
  type: z.literal('security'),
  timestamp: z.number().optional(),
  data: z.object({
    event_type: z.enum(['auth_failure', 'rate_limit_exceeded', 'suspicious_activity', 'data_breach_attempt', 'unauthorized_access']),
    severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    description: z.string(),
    source_ip: z.string().optional(),
    user_agent: z.string().optional(),
    endpoint: z.string().optional(),
    request_method: z.string().optional(),
    threat_level: z.number().min(0).max(100).default(0),
    threat_indicators: z.array(z.string()).optional(),
    blocked: z.boolean().default(false),
    metadata: z.record(z.any()).optional()
  })
})

const ComplianceLogSchema = z.object({
  agent_id: z.string().uuid(),
  type: z.literal('compliance'),
  timestamp: z.number().optional(),
  data: z.object({
    compliance_type: z.enum(['gdpr', 'hipaa', 'sox', 'pci_dss', 'ccpa']),
    regulation: z.string().optional(),
    requirement: z.string().optional(),
    event_description: z.string(),
    data_processed: z.record(z.any()).optional(),
    processing_purpose: z.string().optional(),
    user_consent: z.boolean().optional(),
    data_retention_days: z.number().optional(),
    data_location: z.string().optional(),
    encryption_status: z.boolean().default(true),
    anonymized: z.boolean().default(false),
    metadata: z.record(z.any()).optional()
  })
})

// Middleware to verify agent exists and is active
async function verifyAgent(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const agentId = req.body.agent_id
    
    if (!agentId) {
      return res.status(400).json({ error: 'agent_id is required' })
    }



    const { data: agent, error } = await supabase
      .from('agents')
      .select('id, status, organization_id')
      .eq('id', agentId)
      .single()

    if (error || !agent) {
      return res.status(404).json({ error: 'Agent not found' })
    }

    if (agent.status !== 'active') {
      return res.status(403).json({ error: 'Agent is not active' })
    }

    req.agent = agent
    next()
  } catch (error) {
    console.error('Error verifying agent:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
}

// POST /api/agents/log - Log agent metrics and errors
router.post('/log', apiLimiter, verifyAgent, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const body = req.body
    const agent = req.agent!

    // Validate request based on type
    let validatedData
    if (body.type === 'request') {
      validatedData = MetricsSchema.parse(body)
    } else if (body.type === 'error') {
      validatedData = ErrorSchema.parse(body)
    } else if (body.type === 'security') {
      validatedData = SecurityEventSchema.parse(body)
    } else if (body.type === 'compliance') {
      validatedData = ComplianceLogSchema.parse(body)
    } else {
      return res.status(400).json({ error: 'Invalid type. Must be "request", "error", "security", or "compliance"' })
    }

    const timestamp = new Date(validatedData.timestamp ? validatedData.timestamp * 1000 : Date.now())

    if (validatedData.type === 'request') {
      // Log metrics
      const { error: metricsError } = await supabase
        .from('agent_metrics')
        .insert({
          agent_id: validatedData.agent_id,
          timestamp: timestamp.toISOString(),
          prompt_tokens: validatedData.data.prompt_tokens,
          completion_tokens: validatedData.data.completion_tokens,
          cost: validatedData.data.cost,
          latency_ms: Math.round(validatedData.data.latency * 1000), // Convert to milliseconds
          success: validatedData.data.success,
          model: validatedData.data.model,
          provider: validatedData.data.provider,
          operation: validatedData.data.operation,
          metadata: validatedData.data.metadata
        })

      if (metricsError) {
        console.error('Error inserting metrics:', metricsError)
        return res.status(500).json({ error: 'Failed to log metrics' })
      }

      // Update agent last_activity
      await supabase
        .from('agents')
        .update({ last_activity: timestamp.toISOString() })
        .eq('id', validatedData.agent_id)

    } else if (validatedData.type === 'error') {
      // Log error
      const { error: errorLogError } = await supabase
        .from('agent_errors')
        .insert({
          agent_id: validatedData.agent_id,
          timestamp: timestamp.toISOString(),
          error_type: 'runtime_error',
          error_message: validatedData.data.error,
          stack_trace: validatedData.data.stack_trace,
          operation: validatedData.data.operation,
          request_data: validatedData.data.metadata
        })

      if (errorLogError) {
        console.error('Error inserting error log:', errorLogError)
        return res.status(500).json({ error: 'Failed to log error' })
      }

      // Update agent status if critical error
      await supabase
        .from('agents')
        .update({ 
          status: 'error',
          last_activity: timestamp.toISOString() 
        })
        .eq('id', validatedData.agent_id)

    } else if (validatedData.type === 'security') {
      // Log security event
      const { error: securityError } = await supabase
        .from('agent_security_events')
        .insert({
          agent_id: validatedData.agent_id,
          timestamp: timestamp.toISOString(),
          event_type: validatedData.data.event_type,
          severity: validatedData.data.severity,
          description: validatedData.data.description,
          source_ip: validatedData.data.source_ip,
          user_agent: validatedData.data.user_agent,
          endpoint: validatedData.data.endpoint,
          request_method: validatedData.data.request_method,
          threat_level: validatedData.data.threat_level,
          threat_indicators: validatedData.data.threat_indicators,
          blocked: validatedData.data.blocked,
          metadata: validatedData.data.metadata
        })

      if (securityError) {
        console.error('Error inserting security event:', securityError)
        return res.status(500).json({ error: 'Failed to log security event' })
      }

      // Update agent status if critical security event
      if (validatedData.data.severity === 'critical' || validatedData.data.blocked) {
        await supabase
          .from('agents')
          .update({ 
            status: 'error',
            last_activity: timestamp.toISOString() 
          })
          .eq('id', validatedData.agent_id)
      }

    } else if (validatedData.type === 'compliance') {
      // Log compliance event
      const { error: complianceError } = await supabase
        .from('agent_compliance_logs')
        .insert({
          agent_id: validatedData.agent_id,
          timestamp: timestamp.toISOString(),
          compliance_type: validatedData.data.compliance_type,
          regulation: validatedData.data.regulation,
          requirement: validatedData.data.requirement,
          event_description: validatedData.data.event_description,
          data_processed: validatedData.data.data_processed,
          processing_purpose: validatedData.data.processing_purpose,
          user_consent: validatedData.data.user_consent,
          data_retention_days: validatedData.data.data_retention_days,
          data_location: validatedData.data.data_location,
          encryption_status: validatedData.data.encryption_status,
          anonymized: validatedData.data.anonymized,
          metadata: validatedData.data.metadata
        })

      if (complianceError) {
        console.error('Error inserting compliance log:', complianceError)
        return res.status(500).json({ error: 'Failed to log compliance event' })
      }
    }

    res.status(200).json({ success: true, message: 'Data logged successfully' })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ 
        error: 'Validation error', 
        details: error.errors 
      })
    }
    
    console.error('Error in /api/agents/log:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// POST /api/agents/health - Log agent health status
router.post('/health', apiLimiter, verifyAgent, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const validatedData = HealthSchema.parse(req.body)
    const agent = req.agent!

    const timestamp = new Date(validatedData.timestamp ? validatedData.timestamp * 1000 : Date.now())

    // Log health data
    const { error: healthError } = await supabase
      .from('agent_health')
      .insert({
        agent_id: validatedData.agent_id,
        timestamp: timestamp.toISOString(),
        status: validatedData.data.status,
        memory_usage_mb: validatedData.data.memory_usage,
        cpu_usage_percent: validatedData.data.cpu_usage,
        response_time_ms: validatedData.data.response_time ? Math.round(validatedData.data.response_time * 1000) : null,
        uptime_seconds: validatedData.data.uptime,
        error_count: validatedData.data.error_count || 0,
        last_error: validatedData.data.last_error,
        metadata: validatedData.data.metadata
      })

    if (healthError) {
      console.error('Error inserting health data:', healthError)
      return res.status(500).json({ error: 'Failed to log health data' })
    }

    // Update agent status based on health
    let agentStatus = 'active'
    if (validatedData.data.status === 'unhealthy' || validatedData.data.status === 'offline') {
      agentStatus = 'error'
    }

    await supabase
      .from('agents')
      .update({ 
        status: agentStatus,
        last_activity: timestamp.toISOString() 
      })
      .eq('id', validatedData.agent_id)

    res.status(200).json({ success: true, message: 'Health data logged successfully' })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ 
        error: 'Validation error', 
        details: error.errors 
      })
    }
    
    console.error('Error in /api/agents/health:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// GET /api/agents - Get all agents with their latest metrics (for dashboard)
router.get('/', async (req, res) => {
  try {
    // Get all agents with their latest metrics
    const { data: agents, error: agentsError } = await supabase
      .from('agents')
      .select(`
        *,
        agent_metrics (
          prompt_tokens,
          completion_tokens,
          total_tokens,
          cost,
          latency_ms,
          success,
          model,
          provider,
          timestamp
        ),
        agent_health (
          status,
          memory_usage_mb,
          cpu_usage_percent,
          response_time_ms,
          uptime_seconds,
          error_count,
          timestamp
        )
      `)
      .order('created_at', { ascending: false })

    if (agentsError) {
      console.error('Error fetching agents:', agentsError)
      return res.status(500).json({ error: 'Failed to fetch agents' })
    }

    // Process and aggregate the data
    const processedAgents = agents?.map((agent: any) => {
      const metrics = agent.agent_metrics || []
      const health = agent.agent_health || []

      // Calculate aggregated metrics
      const totalTokens = metrics.reduce((sum: number, m: any) => sum + (m.total_tokens || 0), 0)
      const totalCost = metrics.reduce((sum: number, m: any) => sum + (m.cost || 0), 0)
      const successfulRequests = metrics.filter((m: any) => m.success).length
      const totalRequests = metrics.length
      const avgLatency = metrics.length > 0 
        ? metrics.reduce((sum: number, m: any) => sum + (m.latency_ms || 0), 0) / metrics.length 
        : 0

      // Get latest health status
      const latestHealth = health.length > 0 
        ? health.sort((a: any, b: any) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
        : null

      return {
        id: agent.id,
        name: agent.name,
        description: agent.description,
        agent_type: agent.agent_type,
        provider: agent.provider,
        model: agent.model,
        framework: agent.framework,
        status: agent.status,
        created_at: agent.created_at,
        last_activity: agent.last_activity,
        metrics: {
          total_tokens: totalTokens,
          total_cost: totalCost,
          total_requests: totalRequests,
          success_rate: totalRequests > 0 ? (successfulRequests / totalRequests) * 100 : 0,
          avg_latency_ms: Math.round(avgLatency)
        },
        health: latestHealth ? {
          status: latestHealth.status,
          memory_usage_mb: latestHealth.memory_usage_mb,
          cpu_usage_percent: latestHealth.cpu_usage_percent,
          response_time_ms: latestHealth.response_time_ms,
          uptime_seconds: latestHealth.uptime_seconds,
          error_count: latestHealth.error_count,
          last_check: latestHealth.timestamp
        } : null
      }
    })

    res.status(200).json({ 
      success: true, 
      agents: processedAgents,
      total: processedAgents?.length || 0
    })

  } catch (error) {
    console.error('Error in /api/agents:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// GET /api/agents/:id/metrics - Get detailed metrics for specific agent
router.get('/:id/metrics', async (req, res) => {
  try {
    const agentId = req.params.id
    const { timeframe = '24h' } = req.query

    // Calculate date range based on timeframe
    let startDate = new Date()
    switch (timeframe) {
      case '1h':
        startDate.setHours(startDate.getHours() - 1)
        break
      case '24h':
        startDate.setDate(startDate.getDate() - 1)
        break
      case '7d':
        startDate.setDate(startDate.getDate() - 7)
        break
      case '30d':
        startDate.setDate(startDate.getDate() - 30)
        break
      default:
        startDate.setDate(startDate.getDate() - 1) // Default to 24h
    }

    const { data: metrics, error } = await supabase
      .from('agent_metrics')
      .select('*')
      .eq('agent_id', agentId)
      .gte('timestamp', startDate.toISOString())
      .order('timestamp', { ascending: true })

    if (error) {
      console.error('Error fetching agent metrics:', error)
      return res.status(500).json({ error: 'Failed to fetch metrics' })
    }

    res.status(200).json({ 
      success: true, 
      metrics: metrics || [],
      timeframe,
      agent_id: agentId
    })

  } catch (error) {
    console.error('Error in /api/agents/:id/metrics:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

export default router 