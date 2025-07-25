import { useState, useEffect, useCallback } from 'react';
import { agentApi, type Agent, type AgentMetrics, ApiError } from '@/lib/api';

interface UseAgentsReturn {
  agents: Agent[];
  loading: boolean;
  error: string | null;
  refreshAgents: () => Promise<void>;
  getAgentMetrics: (agentId: string, timeframe?: '1h' | '24h' | '7d' | '30d') => Promise<AgentMetrics | null>;
}

export function useAgents(organizationId?: string): UseAgentsReturn {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshAgents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await agentApi.getAgents(organizationId);
      setAgents(response.agents);
    } catch (err) {
      const errorMessage = err instanceof ApiError 
        ? `API Error (${err.status}): ${err.message}`
        : err instanceof Error 
          ? err.message 
          : 'Failed to fetch agents';
      
      setError(errorMessage);
      console.error('Failed to fetch agents:', err);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  const getAgentMetrics = useCallback(async (
    agentId: string, 
    timeframe: '1h' | '24h' | '7d' | '30d' = '24h'
  ): Promise<AgentMetrics | null> => {
    try {
      return await agentApi.getAgentMetrics(agentId, timeframe);
    } catch (err) {
      console.error('Failed to fetch agent metrics:', err);
      return null;
    }
  }, []);

  useEffect(() => {
    refreshAgents();
  }, [refreshAgents]);

  return {
    agents,
    loading,
    error,
    refreshAgents,
    getAgentMetrics,
  };
}

interface UseAgentMetricsReturn {
  metrics: AgentMetrics | null;
  loading: boolean;
  error: string | null;
  refreshMetrics: () => Promise<void>;
}

export function useAgentMetrics(
  agentId: string,
  timeframe: '1h' | '24h' | '7d' | '30d' = '24h'
): UseAgentMetricsReturn {
  const [metrics, setMetrics] = useState<AgentMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshMetrics = useCallback(async () => {
    if (!agentId) return;

    try {
      setLoading(true);
      setError(null);
      
      const data = await agentApi.getAgentMetrics(agentId, timeframe);
      setMetrics(data);
    } catch (err) {
      const errorMessage = err instanceof ApiError 
        ? `API Error (${err.status}): ${err.message}`
        : err instanceof Error 
          ? err.message 
          : 'Failed to fetch metrics';
      
      setError(errorMessage);
      console.error('Failed to fetch agent metrics:', err);
    } finally {
      setLoading(false);
    }
  }, [agentId, timeframe]);

  useEffect(() => {
    refreshMetrics();
  }, [refreshMetrics]);

  return {
    metrics,
    loading,
    error,
    refreshMetrics,
  };
} 