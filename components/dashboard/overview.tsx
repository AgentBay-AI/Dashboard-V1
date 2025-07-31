import { useEffect, useState } from 'react';
import { apiClient } from '../../lib/api';
import type { DashboardOverview } from '../../lib/api';

export default function DashboardOverview() {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const overview = await apiClient.dashboard.getOverview();
        setData(overview);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to fetch dashboard data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div>Loading dashboard data...</div>;
  }

  if (error) {
    return (
      <div className="text-red-500">
        Error: {error}
      </div>
    );
  }

  if (!data) {
    return <div>No data available</div>;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 p-4">
      {/* Agents Overview */}
      <div className="bg-white rounded-lg shadow p-4">
        <h3 className="text-lg font-semibold mb-2">Agents</h3>
        <div className="space-y-2">
          <div>Total: {data.agents.total}</div>
          <div className="text-green-500">Active: {data.agents.active}</div>
          <div className="text-yellow-500">Idle: {data.agents.idle}</div>
          <div className="text-red-500">Error: {data.agents.error}</div>
        </div>
      </div>

      {/* Conversations */}
      <div className="bg-white rounded-lg shadow p-4">
        <h3 className="text-lg font-semibold mb-2">Conversations</h3>
        <div className="space-y-2">
          <div>Today: {data.conversations.total_today}</div>
          <div>Active: {data.conversations.active}</div>
          <div>Avg Response: {data.conversations.avg_response_time_ms}ms</div>
          <div>Quality: {data.conversations.avg_quality_score}</div>
        </div>
      </div>

      {/* LLM Usage */}
      <div className="bg-white rounded-lg shadow p-4">
        <h3 className="text-lg font-semibold mb-2">LLM Usage</h3>
        <div className="space-y-2">
          <div>Tokens Today: {data.llm_usage.total_tokens_today}</div>
          <div>Cost: ${data.llm_usage.cost_estimate_usd.toFixed(2)}</div>
          <div>Top Models:</div>
          <ul className="list-disc list-inside">
            {data.llm_usage.top_models.map((model, i) => (
              <li key={i}>{model}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Security */}
      <div className="bg-white rounded-lg shadow p-4">
        <h3 className="text-lg font-semibold mb-2">Security</h3>
        <div className="space-y-2">
          <div className="text-red-500">
            Tamper Events: {data.security.tamper_events}
          </div>
          <div className="text-yellow-500">
            PII Detections: {data.security.pii_detections}
          </div>
          <div className="text-orange-500">
            Unclosed Sessions: {data.security.unclosed_sessions}
          </div>
        </div>
      </div>

      <div className="col-span-full text-sm text-gray-500 mt-2">
        Last Updated: {new Date(data.last_updated).toLocaleString()}
      </div>
    </div>
  );
} 