/**
 * API service functions for connecting to the HR Agent backend
 */

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080';

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

interface Agent {
  id: string;
  name: string;
  description?: string;
  organization_id: string;
  provider: string;
  framework?: string;
  model: string;
  status: 'active' | 'inactive' | 'error';
  agent_type: 'custom' | 'nocode';
  endpoint?: string;
  no_code_platform?: string;
  created_at: string;
  updated_at: string;
  last_sync?: string;
  metrics?: {
    performance: number;
    cost: number;
    requests: number;
    latency: number;
    uptime: number;
    health_status: string;
  };
}

interface AgentMetrics {
  agent_id: string;
  timeframe: string;
  metrics: Array<{
    id: string;
    total_tokens: number;
    input_tokens: number;
    output_tokens: number;
    total_cost: number;
    total_requests: number;
    average_latency: number;
    success_rate: number;
    timestamp: string;
    created_at: string;
  }>;
  health: Array<{
    id: string;
    status: 'healthy' | 'warning' | 'critical';
    uptime: number;
    response_time: number;
    error_rate: number;
    cpu_usage?: number;
    memory_usage?: number;
    created_at: string;
  }>;
  errors: Array<{
    id: string;
    error_type: string;
    error_message: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    created_at: string;
  }>;
  summary: {
    total_requests: number;
    total_cost: number;
    average_latency: number;
    error_count: number;
    uptime_average: number;
  };
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function apiRequest<T>(endpoint: string, options?: RequestInit): Promise<T> {
  try {
    const response = await fetch(`${BACKEND_URL}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
      ...options,
    });

    if (!response.ok) {
      throw new ApiError(response.status, `API request failed: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new Error(`Network error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export const agentApi = {
  /**
   * Get all agents with their metrics
   */
  async getAgents(organizationId?: string): Promise<{ agents: Agent[]; total: number }> {
    const params = organizationId ? `?organization_id=${organizationId}` : '';
    return apiRequest<{ agents: Agent[]; total: number }>(`/api/agents${params}`);
  },

  /**
   * Get detailed metrics for a specific agent
   */
  async getAgentMetrics(
    agentId: string,
    timeframe: '1h' | '24h' | '7d' | '30d' = '24h'
  ): Promise<AgentMetrics> {
    return apiRequest<AgentMetrics>(`/api/agents/${agentId}/metrics?timeframe=${timeframe}`);
  },

  /**
   * Log agent metrics (for testing purposes)
   */
  async logMetrics(data: {
    agent_id: string;
    total_tokens?: number;
    input_tokens?: number;
    output_tokens?: number;
    total_cost?: number;
    total_requests?: number;
    average_latency?: number;
    success_rate?: number;
  }): Promise<{ success: boolean; message: string }> {
    return apiRequest<{ success: boolean; message: string }>('/api/agents/log', {
      method: 'POST',
      body: JSON.stringify({
        type: 'metrics',
        data,
      }),
    });
  },

  /**
   * Log agent health status
   */
  async logHealth(data: {
    agent_id: string;
    status: 'healthy' | 'warning' | 'critical';
    uptime?: number;
    response_time?: number;
    error_rate?: number;
    cpu_usage?: number;
    memory_usage?: number;
  }): Promise<{ success: boolean; message: string }> {
    return apiRequest<{ success: boolean; message: string }>('/api/agents/health', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  /**
   * Log agent error
   */
  async logError(data: {
    agent_id: string;
    error_type: string;
    error_message: string;
    stack_trace?: string;
    context?: any;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }): Promise<{ success: boolean; message: string }> {
    return apiRequest<{ success: boolean; message: string }>('/api/agents/log', {
      method: 'POST',
      body: JSON.stringify({
        type: 'error',
        data,
      }),
    });
  },

  /**
   * Log security event
   */
  async logSecurityEvent(data: {
    agent_id: string;
    event_type: string;
    description: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    source_ip?: string;
    user_agent?: string;
    metadata?: any;
  }): Promise<{ success: boolean; message: string }> {
    return apiRequest<{ success: boolean; message: string }>('/api/agents/log', {
      method: 'POST',
      body: JSON.stringify({
        type: 'security',
        data,
      }),
    });
  },

  /**
   * Log compliance event
   */
  async logComplianceEvent(data: {
    agent_id: string;
    compliance_type: string;
    status: 'compliant' | 'non_compliant' | 'warning';
    details: string;
    metadata?: any;
  }): Promise<{ success: boolean; message: string }> {
    return apiRequest<{ success: boolean; message: string }>('/api/agents/log', {
      method: 'POST',
      body: JSON.stringify({
        type: 'compliance',
        data,
      }),
    });
  },
};

export const healthApi = {
  /**
   * Check if the backend is healthy
   */
  async checkHealth(): Promise<{
    status: string;
    timestamp: string;
    version: string;
    environment: string;
    uptime: number;
  }> {
    return apiRequest<{
      status: string;
      timestamp: string;
      version: string;
      environment: string;
      uptime: number;
    }>('/health');
  },
};

export { ApiError };
export type { Agent, AgentMetrics }; 