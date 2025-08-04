import axios, { AxiosInstance } from 'axios';

interface CreateAgentData {
  agentName: string;
  agentDescription?: string;
  agentType: string;
  agentUseCase?: string;
  llmProviders?: string[];
  platform?: string;
}

interface Agent {
  id: string;
  name: string;
  description?: string;
  type: string;
  capabilities?: string;
  llm_providers?: string[];
  platform?: string;
  status: string;
  created_at: string;
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

// Create axios instance with default config
const api: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${import.meta.env.VITE_API_KEY}`
  }
});

// Add response interceptor for debugging
api.interceptors.response.use(
  (response) => {
    console.log('API response received:', response.status, response.config.url);
    return response;
  },
  (error) => {
    console.error('API response error:', error);
    return Promise.reject(error);
  }
);

export const apiClient = {
  agents: {
    // Create a new agent
    create: async (data: CreateAgentData): Promise<ApiResponse<Agent>> => {
      try {
        const response = await api.post<ApiResponse<Agent>>('/agents', data);
        return response.data;
      } catch (error) {
        console.error('Failed to create agent:', error);
        throw error;
      }
    },

    // List all agents
    list: async (): Promise<ApiResponse<Agent[]>> => {
      try {
        const response = await api.get<ApiResponse<Agent[]>>('/agents');
        return response.data;
      } catch (error) {
        console.error('Failed to list agents:', error);
        throw error;
      }
    },

    // Delete an agent
    delete: async (id: string): Promise<ApiResponse<{ id: string }>> => {
      try {
        const response = await api.delete<ApiResponse<{ id: string }>>(`/agents/${id}`);
        return response.data;
      } catch (error) {
        console.error('Failed to delete agent:', error);
        throw error;
      }
    }
  }
}; 