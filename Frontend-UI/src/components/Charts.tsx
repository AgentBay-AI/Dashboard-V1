import { useState, useEffect } from "react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell } from "recharts";
import { apiClient } from "@/lib/api";

// Default data structure for fallback
const defaultPerformanceData = [
  { time: "00:00", successRate: 0, responseTime: 0, sessions: 0 },
  { time: "04:00", successRate: 0, responseTime: 0, sessions: 0 },
  { time: "08:00", successRate: 0, responseTime: 0, sessions: 0 },
  { time: "12:00", successRate: 0, responseTime: 0, sessions: 0 },
  { time: "16:00", successRate: 0, responseTime: 0, sessions: 0 },
  { time: "20:00", successRate: 0, responseTime: 0, sessions: 0 }
];

const systemHealthData = [
  { time: "00:00", cpu: 45, memory: 62, storage: 34 },
  { time: "04:00", cpu: 52, memory: 68, storage: 35 },
  { time: "08:00", cpu: 78, memory: 72, storage: 38 },
  { time: "12:00", cpu: 68, memory: 74, storage: 42 },
  { time: "16:00", cpu: 72, memory: 69, storage: 45 },
  { time: "20:00", cpu: 58, memory: 65, storage: 48 }
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

interface CustomTooltipProps {
  active?: boolean;
  payload?: any[];
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
  const [hoveredData, setHoveredData] = useState<any>(null);
  const [performanceData, setPerformanceData] = useState(defaultPerformanceData);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await apiClient.getPerformanceData();
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
  }, []);

  return (
    <div className="w-full">
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
            content={<CustomTooltip description="Agent performance metrics over 24 hours" />}
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
  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={costBreakdownData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={5}
            dataKey="cost"
          >
            {costBreakdownData.map((entry, index) => (
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
                      Percentage: {data.value}%
                    </p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
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