import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8080/api';
const API_KEY = import.meta.env.VITE_API_KEY || 'test_key_12345';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`,
  },
});

// API response interfaces
export interface DashboardOverview {
  agents: {
    active: number;
    total: number;
    successRate: number;
    avgResponseTime: number;
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

export const apiClient = {
  // Dashboard overview
  getDashboardOverview: async (): Promise<DashboardOverview> => {
    try {
      const { data } = await api.get('/dashboard/overview');
      return {
        agents: {
          active: data.total_agents || 0,
          total: data.total_agents || 0,
          successRate: data.avg_success_rate || 0,
          avgResponseTime: data.avg_response_time || 0
        },
        security: {
          threats: data.security_events || 0,
          riskLevel: data.security_events > 5 ? 'High' : data.security_events > 2 ? 'Medium' : 'Low',
          complianceScore: 95, // Default value
          security_flags: data.security?.security_flags || {
            pii_detected: 0,
            tamper_detected: 0,
            compliance_violation: 0
          }
        },
        costs: {
          totalTokens: data.total_tokens || 0,
          monthlyCost: data.total_cost || 0,
          costPerAgent: data.total_agents > 0 ? (data.total_cost / data.total_agents) : 0
        },
        system: {
          cpu: Math.floor(Math.random() * 30) + 50, // Mock data
          memory: Math.floor(Math.random() * 30) + 60,
          uptime: 99.9
        }
      };
    } catch (error) {
      console.error('Failed to fetch dashboard overview:', error);
      // Return mock data as fallback
      return {
        agents: { active: 0, total: 0, successRate: 0, avgResponseTime: 0 },
        security: { 
          threats: 0, 
          riskLevel: 'Low', 
          complianceScore: 0,
          security_flags: { pii_detected: 0, tamper_detected: 0, compliance_violation: 0 }
        },
        costs: { totalTokens: 0, monthlyCost: 0, costPerAgent: 0 },
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
      const { data } = await api.get('/dashboard/system-health');
      return data.system_health || [];
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
  }
}; 