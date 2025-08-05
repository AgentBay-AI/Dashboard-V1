import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8080/api';
const API_KEY = import.meta.env.VITE_API_KEY;

console.log('API Configuration:', {
  API_BASE_URL,
  API_KEY: API_KEY ? `${API_KEY.substring(0, 10)}...` : 'NOT SET'
});

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`,
  },
});

// Add request interceptor for debugging
api.interceptors.request.use((config: any) => {
  console.log('Making API request:', {
    url: config.url,
    baseURL: config.baseURL,
    headers: {
      Authorization: config.headers.Authorization ? `${config.headers.Authorization.substring(0, 20)}...` : 'NOT SET'
    }
  });
  return config;
}, (error) => {
  console.error('Request interceptor error:', error);
  return Promise.reject(error);
});

// Add response interceptor for debugging
api.interceptors.response.use((response) => {
  console.log('API response received:', response.status, response.config.url);
  return response;
}, (error) => {
  console.error('API response error:', {
    status: error.response?.status,
    url: error.config?.url,
    message: error.message
  });
  return Promise.reject(error);
});

// API response interfaces
export interface DashboardOverview {
  agents: {
    active: number;
    total: number;
    successRate: number;
    avgResponseTime: number;
  };
  conversations: {
    total: number;
    active: number;
    completed: number;
    failed: number;
  };
  security: {
    threats: number;
    riskLevel: string;
    complianceScore: number;
    security_flags: {
      pii_detected: number;
      tamper_detected: number;
      compliance_violation: number;
    };
  };
  costs: {
    totalTokens: number;
    monthlyCost: number;
    costPerAgent: number;
  };
  quality: {
    avgScore: number;
    totalRated: number;
  };
  system: {
    cpu: number;
    memory: number;
    uptime: number;
  };
}

export interface PerformanceData {
  time: string;
  successRate: number;
  responseTime: number;
  sessions: number;
}

export interface SystemHealthData {
  time: string;
  cpu: number;
  memory: number;
  storage: number;
}

export interface SecurityData {
  date: string;
  threats: number;
  piiDetections: number;
  complianceScore: number;
}

export interface CostBreakdownData {
  name: string;
  value: number;
  cost: number;
  agents: number;
}

export interface AgentActivityData {
  agent: string;
  sessions: number;
  avgDuration: number;
  status: string;
}

export interface LLMUsageData {
  timeframe: {
    start: string;
    end: string;
    requested_timeframe: string;
  };
  summary: {
    total_cost: number;
    total_input_tokens: number;
    total_output_tokens: number;
    total_requests: number;
    providers_used: number;
  };
  by_provider: {
    [provider: string]: {
      input_tokens: number;
      output_tokens: number;
      cost: number;
      request_count: number;
      models: number;
    };
  };
  detailed: {
    [provider: string]: {
      [model: string]: {
        input_tokens: number;
        output_tokens: number;
        cost: number;
        request_count: number;
      };
    };
  };
}

export interface TopModel {
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cost: number;
  request_count: number;
}

export interface Agent {
  agent_id: string;
  id?: string;
  name?: string;
  description?: string;
  type?: string;
  capabilities?: string;
  llm_providers?: string[];
  platform?: string;
  status: string;
  registration_time: string;
  sdk_version?: string;
  metadata: Record<string, any>;
}

interface CreateAgentData {
  agentName: string;
  agentDescription?: string;
  agentType: string;
  agentUseCase?: string;
  llmProviders?: string[];
  platform?: string;
}

export interface AgentActivity {
  agent_id: string;
  activity_type: string;
  timestamp: string;
  details: Record<string, any>;
  duration: number | null;
}

export interface OperationsOverview {
  active_agents: Agent[];
  status_distribution: Record<string, number>;
  recent_activity: AgentActivity[];
}

export interface MetricsOverview {
  agent_id: string;
  total_sessions: number;
  successful_sessions: number;
  failed_sessions: number;
  success_rate_percent: number;
  avg_response_time_ms: number | null;
  avg_quality_score: number | null;
  last_updated: string;
}

export interface ActiveConversation {
  session_id: string;
  agent_id: string;
  status: string;
  start_time: string;
  total_messages: number;
  last_message_time: string;
  duration_minutes: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

export const apiClient = {
  // Dashboard overview
  getDashboardOverview: async (): Promise<DashboardOverview> => {
    try {
      console.log('Fetching dashboard data...');
      
      // Fetch data from multiple endpoints
      const [operationsResponse, llmResponse] = await Promise.all([
        api.get('/agents/operations/overview'),
        api.get('/llm-usage/aggregated?timeframe=24h')
      ]);

      console.log('Operations response:', operationsResponse.data);
      console.log('LLM response:', llmResponse.data);

      const operations = operationsResponse.data.data;
      const llmUsage = llmResponse.data;

      const dashboardData = {
        agents: {
          active: operations.active_agents?.length || 0,
          total: operations.active_agents?.length || 0,
          successRate: 95, // Mock for now
          avgResponseTime: 250 // Mock for now
        },
        conversations: {
          total: 0, // Will be replaced with real data
          active: 0,
          completed: 0,
          failed: 0
        },
        security: {
          threats: 0, // Mock for now
          riskLevel: 'Low' as const,
          complianceScore: 95,
          security_flags: {
            pii_detected: 0,
            tamper_detected: 0,
            compliance_violation: 0
          }
        },
        costs: {
          totalTokens: (llmUsage.summary?.total_input_tokens || 0) + (llmUsage.summary?.total_output_tokens || 0),
          monthlyCost: llmUsage.summary?.total_cost || 0,
          costPerAgent: operations.active_agents?.length > 0 ? 
            (llmUsage.summary?.total_cost || 0) / operations.active_agents.length : 0
        },
        quality: {
          avgScore: 4.2, // Mock for now
          totalRated: 10
        },
        system: {
          cpu: Math.floor(Math.random() * 30) + 50,
          memory: Math.floor(Math.random() * 30) + 60,
          uptime: 99.9
        }
      };

      console.log('Dashboard data processed:', dashboardData);
      return dashboardData;
    } catch (error) {
      console.error('Failed to fetch dashboard overview:', error);
      // Return mock data as fallback
      return {
        agents: { active: 0, total: 0, successRate: 0, avgResponseTime: 0 },
        conversations: { total: 0, active: 0, completed: 0, failed: 0 },
        security: { 
          threats: 0, 
          riskLevel: 'Low', 
          complianceScore: 0,
          security_flags: { pii_detected: 0, tamper_detected: 0, compliance_violation: 0 }
        },
        costs: { totalTokens: 0, monthlyCost: 0, costPerAgent: 0 },
        quality: { avgScore: 0, totalRated: 0 },
        system: { cpu: 0, memory: 0, uptime: 0 }
      };
    }
  },

  // Performance data
  getPerformanceData: async (): Promise<PerformanceData[]> => {
    try {
      const { data } = await api.get('/dashboard/performance');
      return data.performance_data || [];
    } catch (error) {
      console.error('Failed to fetch performance data:', error);
      return [];
    }
  },

  // System health data
  getSystemHealthData: async (): Promise<SystemHealthData[]> => {
    try {
      // Return simulated system health data
      return [{
        time: new Date().toISOString(),
        cpu: Math.floor(Math.random() * 30) + 50, // 50-80%
        memory: Math.floor(Math.random() * 30) + 60, // 60-90%
        storage: Math.floor(Math.random() * 20) + 70 // 70-90%
      }];
    } catch (error) {
      console.error('Failed to fetch system health data:', error);
      return [];
    }
  },

  // Security data
  getSecurityData: async (): Promise<SecurityData[]> => {
    try {
      const { data } = await api.get('/dashboard/security');
      return data.security_data || [];
    } catch (error) {
      console.error('Failed to fetch security data:', error);
      return [];
    }
  },

  // Cost breakdown data
  getCostBreakdownData: async (): Promise<CostBreakdownData[]> => {
    try {
      const { data } = await api.get('/dashboard/cost-breakdown');
      return data.cost_breakdown || [];
    } catch (error) {
      console.error('Failed to fetch cost breakdown data:', error);
      return [];
    }
  },

  // Agent activity data
  getAgentActivityData: async (): Promise<AgentActivityData[]> => {
    try {
      const { data } = await api.get('/dashboard/agent-activity');
      return data.agent_activity || [];
    } catch (error) {
      console.error('Failed to fetch agent activity data:', error);
      return [];
    }
  },

  // LLM usage and cost data
  llm: {
    getUsageAggregated: async (timeframe: string = '24h'): Promise<LLMUsageData> => {
      const { data } = await api.get(`/llm-usage/aggregated?timeframe=${timeframe}`);
      return data;
    },
    getTopModels: async (limit: number = 10, sortBy: string = 'cost'): Promise<{ top_models: TopModel[] }> => {
      const { data } = await api.get(`/llm-usage/top-models?limit=${limit}&sort_by=${sortBy}`);
      return data;
    },
    getPricingInfo: async () => {
      const { data } = await api.get('/llm-usage/pricing-info');
      return data;
    }
  },

  // API Keys
  generateApiKey: async (clientData: { client_id: string; client_name: string; permissions?: string[]; rate_limit_per_minute?: number; expires_at?: string }) => {
    const { data } = await api.post('/api-keys', clientData);
    return data;
  },

  agents: {
    register: async (data: Omit<Agent, 'status'>) => {
      const response = await api.post<ApiResponse<Agent>>('/agents/register', data);
      return response.data;
    },

    updateStatus: async (agentId: string, status: string, metadata?: Record<string, any>) => {
      const response = await api.post<ApiResponse<Agent>>('/agents/status', {
        agent_id: agentId,
        status,
        timestamp: new Date().toISOString(),
        metadata
      });
      return response.data;
    },

    logActivity: async (agentId: string, action: string, details?: Record<string, any>, duration?: number) => {
      const response = await api.post<ApiResponse<AgentActivity>>('/agents/activity', {
        agent_id: agentId,
        action,
        timestamp: new Date().toISOString(),
        details: details || {},
        duration: duration || null
      });
      return response.data;
    },

    getActive: async () => {
      const response = await api.get<ApiResponse<Agent[]>>('/agents/active');
      return response.data;
    },

    getStatus: async (agentId: string) => {
      const response = await api.get<ApiResponse<Agent>>(`/agents/${agentId}/status`);
      return response.data;
    },

    getActivity: async (agentId: string, limit?: number) => {
      const response = await api.get<ApiResponse<AgentActivity[]>>(`/agents/${agentId}/activity${limit ? `?limit=${limit}` : ''}`);
      return response.data;
    },

    getOperationsOverview: async () => {
      const response = await api.get<ApiResponse<OperationsOverview>>('/agents/operations/overview');
      return response.data;
    },

    create: async (data: CreateAgentData) => {
      const response = await api.post<ApiResponse<Agent>>('/agents', data);
      return response.data;
    }
  },

  // Conversation operations
  conversations: {
    start: async (data: any) => {
      const response = await api.post<ApiResponse<any>>('/conversations/start', data);
      return response.data;
    },

    end: async (data: any) => {
      const response = await api.post<ApiResponse<any>>('/conversations/end', data);
      return response.data;
    },

    addMessage: async (data: any) => {
      const response = await api.post<ApiResponse<any>>('/conversations/message', data);
      return response.data;
    },

    getActive: async () => {
      const response = await api.get<ApiResponse<ActiveConversation[]>>('/conversations/active');
      return response.data;
    },

    getHistory: async (sessionId: string) => {
      const response = await api.get<ApiResponse<any[]>>(`/conversations/${sessionId}/history`);
      return response.data;
    }
  },

  // Metrics operations
  metrics: {
    getOverview: async () => {
      const response = await api.get<ApiResponse<MetricsOverview[]>>('/metrics/overview');
      return response.data;
    },

    getSuccessRates: async () => {
      const response = await api.get<ApiResponse<any[]>>('/metrics/success-rates');
      return response.data;
    },

    getResponseTimes: async () => {
      const response = await api.get<ApiResponse<any[]>>('/metrics/response-times');
      return response.data;
    },

    getQuality: async () => {
      const response = await api.get<ApiResponse<any[]>>('/metrics/quality');
      return response.data;
    }
  }
}; 