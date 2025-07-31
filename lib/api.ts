import axios from 'axios';

// Create axios instance with default config
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  }
});

// Add API key to requests
api.interceptors.request.use((config: any) => {
  const apiKey = process.env.NEXT_PUBLIC_API_KEY;
  if (apiKey) {
    config.headers.Authorization = `Bearer ${apiKey}`;
  }
  return config;
});

// API endpoints
export const endpoints = {
  // Agent Operations
  agents: {
    register: '/sdk/agents/register',
    status: '/sdk/agents/status',
    overview: '/sdk/agents/overview',
  },
  
  // Conversations
  conversations: {
    start: '/sdk/conversations/start',
    end: '/sdk/conversations/end',
    resume: '/sdk/conversations/resume',
    getById: (id: string) => `/sdk/conversations/${id}`,
    localExpired: '/sdk/conversations/local-expired',
    failedSession: '/sdk/conversations/failed-session',
  },
  
  // Security
  security: {
    metrics: '/sdk/security/metrics',
    tamper: '/sdk/security/tamper',
  },
  
  // LLM Usage
  llm: {
    usage: '/sdk/llm-usage',
  },
  
  // Compliance
  compliance: {
    audit: '/sdk/compliance/audit',
    acknowledgment: '/sdk/compliance/acknowledgment',
  },
  
  // Dashboard
  dashboard: {
    overview: '/dashboard/overview',
  }
};

// Type definitions for API responses
export interface AgentOverview {
  total_agents: number;
  active_agents: number;
  idle_agents: number;
  error_agents: number;
  maintenance_agents: number;
  last_updated: string;
}

export interface DashboardOverview {
  agents: {
    total: number;
    active: number;
    idle: number;
    error: number;
    maintenance: number;
  };
  conversations: {
    total_today: number;
    active: number;
    avg_response_time_ms: number;
    avg_quality_score: string;
  };
  llm_usage: {
    total_tokens_today: number;
    cost_estimate_usd: number;
    top_models: string[];
  };
  security: {
    tamper_events: number;
    pii_detections: number;
    unclosed_sessions: number;
  };
  last_updated: string;
}

// API functions
export const apiClient = {
  // Agent Operations
  agents: {
    register: async (data: any) => {
      const response = await api.post(endpoints.agents.register, data);
      return response.data;
    },
    updateStatus: async (data: any) => {
      const response = await api.post(endpoints.agents.status, data);
      return response.data;
    },
    getOverview: async (): Promise<AgentOverview> => {
      const response = await api.get(endpoints.agents.overview);
      return response.data;
    },
  },

  // Conversations
  conversations: {
    start: async (data: any) => {
      const response = await api.post(endpoints.conversations.start, data);
      return response.data;
    },
    end: async (data: any) => {
      const response = await api.post(endpoints.conversations.end, data);
      return response.data;
    },
    resume: async (data: any) => {
      const response = await api.post(endpoints.conversations.resume, data);
      return response.data;
    },
    getById: async (id: string) => {
      const response = await api.get(endpoints.conversations.getById(id));
      return response.data;
    },
    reportLocalExpired: async (data: any) => {
      const response = await api.post(endpoints.conversations.localExpired, data);
      return response.data;
    },
    reportFailedSession: async (data: any) => {
      const response = await api.post(endpoints.conversations.failedSession, data);
      return response.data;
    },
  },

  // Security
  security: {
    reportMetrics: async (data: any) => {
      const response = await api.post(endpoints.security.metrics, data);
      return response.data;
    },
    reportTamper: async (data: any) => {
      const response = await api.post(endpoints.security.tamper, data);
      return response.data;
    },
  },

  // LLM Usage
  llm: {
    trackUsage: async (data: any) => {
      const response = await api.post(endpoints.llm.usage, data);
      return response.data;
    },
  },

  // Compliance
  compliance: {
    submitAudit: async (data: any) => {
      const response = await api.post(endpoints.compliance.audit, data);
      return response.data;
    },
    submitAcknowledgment: async (data: any) => {
      const response = await api.post(endpoints.compliance.acknowledgment, data);
      return response.data;
    },
  },

  // Dashboard
  dashboard: {
    getOverview: async (): Promise<DashboardOverview> => {
      const response = await api.get(endpoints.dashboard.overview);
      return response.data;
    },
  },
};

export default api; 