import { useState, useEffect, useMemo } from "react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell } from "recharts";
import { apiClient, LLMUsageData } from "@/lib/api";
import { Button } from "./ui/button";

// Default data structure for fallback
const defaultPerformanceData = [
  { time: "00:00", successRate: 85, responseTime: 2.8, sessions: 12 },
  { time: "04:00", successRate: 88, responseTime: 2.4, sessions: 18 },
  { time: "08:00", successRate: 92, responseTime: 2.1, sessions: 25 },
  { time: "12:00", successRate: 94, responseTime: 1.9, sessions: 32 },
  { time: "16:00", successRate: 96, responseTime: 1.6, sessions: 28 },
  { time: "20:00", successRate: 98, responseTime: 1.2, sessions: 22 }
];

const systemHealthData = [
  { time: "00:00", cpu: 45, memory: 62, storage: 34 },
  { time: "04:00", cpu: 52, memory: 68, storage: 35 },
  { time: "08:00", cpu: 78, memory: 72, storage: 38 },
  { time: "12:00", cpu: 68, memory: 74, storage: 42 },
  { time: "16:00", cpu: 72, memory: 69, storage: 45 },
  { time: "20:00", cpu: 58, memory: 65, storage: 48 },
];

const costBreakdownData = [
  { name: "OpenAI GPT-4", value: 42, cost: 1247, agents: 8 },
  { name: "Anthropic Claude", value: 25, cost: 672, agents: 5 },
  { name: "Google Gemini", value: 18, cost: 359, agents: 4 },
  { name: "OpenAI GPT-3.5", value: 10, cost: 120, agents: 3 },
  { name: "Multiple LLMs", value: 5, cost: 89, agents: 2 }
];

const securityData = [
  { date: "Mon", threats: 3, piiDetections: 12, complianceScore: 95 },
  { date: "Tue", threats: 1, piiDetections: 8, complianceScore: 97 },
  { date: "Wed", threats: 5, piiDetections: 15, complianceScore: 93 },
  { date: "Thu", threats: 2, piiDetections: 6, complianceScore: 98 },
  { date: "Fri", threats: 4, piiDetections: 11, complianceScore: 96 },
  { date: "Sat", threats: 1, piiDetections: 4, complianceScore: 99 },
  { date: "Sun", threats: 2, piiDetections: 7, complianceScore: 97 }
];

const agentActivityData = [
  { agent: "AI-001", sessions: 45, avgDuration: 8.5, status: "active" },
  { agent: "AI-002", sessions: 38, avgDuration: 12.3, status: "active" },
  { agent: "AI-003", sessions: 52, avgDuration: 6.8, status: "active" },
  { agent: "AI-004", sessions: 29, avgDuration: 15.2, status: "idle" },
  { agent: "AI-005", sessions: 41, avgDuration: 9.7, status: "active" }
];

const COLORS = ['hsl(var(--chart-1))', 'hsl(var(--chart-2))', 'hsl(var(--chart-3))', 'hsl(var(--chart-4))', 'hsl(var(--chart-5))'];

interface TooltipPayload {
  value: number | string;
  name: string;
  color: string;
  unit?: string;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayload[];
  label?: string;
  description?: string;
}

const CustomTooltip = ({ active, payload, label, description }: CustomTooltipProps) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-popover border border-border rounded-lg p-3 shadow-lg animate-fade-in">
        <p className="font-medium text-foreground">{`${label || 'Value'}`}</p>
        {description && (
          <p className="text-xs text-muted-foreground mb-2">{description}</p>
        )}
        {payload.map((entry, index) => (
          <p key={index} className="text-sm" style={{ color: entry.color }}>
            {`${entry.name}: ${entry.value}${entry.unit || ''}`}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

export const PerformanceChart = () => {
  const [hoveredData, setHoveredData] = useState<unknown>(null);
  const [performanceData, setPerformanceData] = useState(defaultPerformanceData);
  const [hoursWindow, setHoursWindow] = useState<number>(24);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const timeframe = `${hoursWindow}h`;
        const data = await apiClient.getPerformanceData(undefined, { timeframe });
        if (data.length > 0) {
          setPerformanceData(data);
        }
      } catch (error) {
        console.error('Failed to fetch performance data:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [hoursWindow]);

  const incWindow = () => setHoursWindow((h) => Math.min(h + 24, 168));
  const resetWindow = () => setHoursWindow(24);

  const label = hoursWindow <= 24 ? 'Last 24h' : `Last ${Math.ceil(hoursWindow/24)} days`;

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={resetWindow}>Reset</Button>
          <Button variant="default" size="sm" onClick={incWindow} disabled={hoursWindow >= 168}>Expand (+24h)</Button>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={performanceData} onMouseMove={(data) => setHoveredData(data)}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="time" 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <Tooltip 
            content={<CustomTooltip description="Agent performance metrics over selected window" />}
            cursor={{ stroke: 'hsl(var(--primary))', strokeWidth: 1 }}
          />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="successRate" 
            stroke="hsl(var(--chart-1))" 
            strokeWidth={2}
            dot={{ fill: 'hsl(var(--chart-1))', strokeWidth: 2, r: 4 }}
            name="Success Rate (%)"
            activeDot={{ r: 6, stroke: 'hsl(var(--chart-1))', strokeWidth: 2, fill: 'hsl(var(--background))' }}
          />
          <Line 
            type="monotone" 
            dataKey="responseTime" 
            stroke="hsl(var(--chart-2))" 
            strokeWidth={2}
            dot={{ fill: 'hsl(var(--chart-2))', strokeWidth: 2, r: 4 }}
            name="Response Time (s)"
            activeDot={{ r: 6, stroke: 'hsl(var(--chart-2))', strokeWidth: 2, fill: 'hsl(var(--background))' }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export const SystemHealthChart = () => {
  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={systemHealthData}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="time" 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <Tooltip 
            content={<CustomTooltip description="Real-time system resource usage" />}
            cursor={{ stroke: 'hsl(var(--primary))', strokeWidth: 1 }}
          />
          <Legend />
          <Area 
            type="monotone" 
            dataKey="cpu" 
            stackId="1"
            stroke="hsl(var(--chart-1))" 
            fill="hsl(var(--chart-1) / 0.6)"
            name="CPU (%)"
          />
          <Area 
            type="monotone" 
            dataKey="memory" 
            stackId="1"
            stroke="hsl(var(--chart-2))" 
            fill="hsl(var(--chart-2) / 0.6)"
            name="Memory (%)"
          />
          <Area 
            type="monotone" 
            dataKey="storage" 
            stackId="1"
            stroke="hsl(var(--chart-3))" 
            fill="hsl(var(--chart-3) / 0.6)"
            name="Storage (%)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export const CostBreakdownChart = () => {
  const [llmUsageData, setLlmUsageData] = useState<LLMUsageData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await apiClient.llm.getUsageAggregated('24h');
        console.log('LLM Usage Data:', data); // Debug log
        setLlmUsageData(data);
      } catch (error) {
        console.error('Failed to fetch LLM usage data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  // Transform LLM usage data into pie chart format
  const chartData = useMemo(() => {
    if (!llmUsageData?.detailed) return [];
    
    return Object.entries(llmUsageData.detailed).flatMap(([provider, models]) =>
      Object.entries(models).map(([model, data]) => {
        const percentage = (data.cost / (llmUsageData.summary?.total_cost || 1)) * 100;
        return {
          name: `${provider} ${model}`,
          value: data.cost, // Use actual cost as value
          displayValue: percentage.toFixed(2), // Store percentage for display
          cost: data.cost.toFixed(4),
          tokens: data.input_tokens + data.output_tokens,
          requests: data.request_count
        };
      })
    );
  }, [llmUsageData]);

  console.log('Chart Data:', chartData); // Debug log

  return (
    <div className="w-full">
      {loading ? (
        <div className="flex items-center justify-center h-[300px] text-muted-foreground">
          Loading cost data...
        </div>
      ) : chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={5}
              dataKey="value"
              nameKey="name"
              
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip 
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="bg-popover border border-border rounded-lg p-3 shadow-lg animate-fade-in">
                      <p className="font-medium text-foreground">{data.name}</p>
                      <p className="text-sm text-muted-foreground">Cost Breakdown Analysis</p>
                      <p className="text-sm" style={{ color: payload[0].color }}>
                        Cost: ${data.cost}
                      </p>
                      <p className="text-sm" style={{ color: payload[0].color }}>
                        Percentage: {data.displayValue}%
                      </p>
                      <p className="text-sm" style={{ color: payload[0].color }}>
                        Total Tokens: {data.tokens.toLocaleString()}
                      </p>
                      <p className="text-sm" style={{ color: payload[0].color }}>
                        Requests: {data.requests}
                      </p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Legend formatter={(value) => value.split(' ')[0]} /> {/* Show only provider name in legend */}
          </PieChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-[300px] text-muted-foreground">
          No cost data available
        </div>
      )}
    </div>
  );
};

export const SecurityChart = () => {
  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={securityData}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="date" 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <Tooltip 
            content={<CustomTooltip description="Weekly security monitoring and compliance scores" />}
            cursor={{ fill: 'hsl(var(--muted) / 0.3)' }}
          />
          <Legend />
          <Bar 
            dataKey="threats" 
            fill="hsl(var(--destructive))" 
            name="Threats Detected"
            radius={[2, 2, 0, 0]}
          />
          <Bar 
            dataKey="piiDetections" 
            fill="hsl(var(--warning))" 
            name="PII Detections"
            radius={[2, 2, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export const AgentActivityChart = () => {
  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={agentActivityData}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="agent" 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <Tooltip 
            content={({ active, payload, label }) => {
              if (active && payload && payload.length) {
                const data = payload[0].payload;
                return (
                  <div className="bg-popover border border-border rounded-lg p-3 shadow-lg animate-fade-in">
                    <p className="font-medium text-foreground">{label}</p>
                    <p className="text-sm text-muted-foreground">Agent Activity Details</p>
                    <p className="text-sm">Sessions: {data.sessions}</p>
                    <p className="text-sm">Avg Duration: {data.avgDuration}min</p>
                    <p className="text-sm">Status: 
                      <span className={`ml-1 px-2 py-1 rounded text-xs ${
                        data.status === 'active' ? 'bg-success/20 text-success' : 'bg-muted text-muted-foreground'
                      }`}>
                        {data.status}
                      </span>
                    </p>
                  </div>
                );
              }
              return null;
            }}
            cursor={{ fill: 'hsl(var(--muted) / 0.3)' }}
          />
          <Legend />
          <Bar 
            dataKey="sessions" 
            fill="hsl(var(--chart-1))" 
            name="Sessions Handled"
            radius={[2, 2, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export const SessionDurationChart = () => {
  const sessionData = [
    { hour: "00", avgDuration: 8.2, totalSessions: 12 },
    { hour: "04", avgDuration: 12.1, totalSessions: 8 },
    { hour: "08", avgDuration: 6.8, totalSessions: 25 },
    { hour: "12", avgDuration: 9.4, totalSessions: 32 },
    { hour: "16", avgDuration: 7.6, totalSessions: 28 },
    { hour: "20", avgDuration: 11.3, totalSessions: 18 }
  ];

  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={sessionData}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="hour" 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <Tooltip 
            content={<CustomTooltip description="Average session duration and volume by hour" />}
            cursor={{ stroke: 'hsl(var(--primary))', strokeWidth: 1 }}
          />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="avgDuration" 
            stroke="hsl(var(--chart-2))" 
            strokeWidth={3}
            dot={{ fill: 'hsl(var(--chart-2))', strokeWidth: 2, r: 5 }}
            name="Avg Duration (min)"
            activeDot={{ r: 8, stroke: 'hsl(var(--chart-2))', strokeWidth: 2, fill: 'hsl(var(--background))' }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};