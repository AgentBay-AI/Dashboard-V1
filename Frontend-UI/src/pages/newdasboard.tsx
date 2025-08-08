import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { 
  PerformanceChart, 
  SystemHealthChart, 
  CostBreakdownChart, 
  SecurityChart, 
  AgentActivityChart,
  SessionDurationChart 
} from "@/components/Charts";
import LineBackground from "@/components/LineBackground";
import { useTheme } from "@/components/ThemeProvider";
import { 
  Activity, 
  Users, 
  Shield, 
  DollarSign, 
  Clock, 
  Server, 
  Plus,
  Settings,
  TrendingUp,
  Eye,
  BarChart3,
  PieChart,
  Sun,
  Moon
} from "lucide-react";
import axios from 'axios';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();

  const [filters, setFilters] = useState<{ organizationId?: string; agentId?: string }>({});
  const [organizations, setOrganizations] = useState<Array<{ id: string; name: string }>>([]);
  const [agents, setAgents] = useState<any[]>([]);
  const [recentActivity, setRecentActivity] = useState<any[]>([]);

  const [dashboardData, setDashboardData] = useState({
    agents: { active: 0, total: 0, successRate: 0, avgResponseTime: 0 },
    security: { threats: 0, riskLevel: "Low", complianceScore: 100 },
    costs: { totalTokens: 0, monthlyCost: 0, costPerAgent: 0 },
    system: { cpu: Math.floor(Math.random() * 30) + 50, memory: Math.floor(Math.random() * 30) + 60, uptime: 99.9 }
  });

  const apiKey = import.meta.env.VITE_API_KEY;
  const baseURL = import.meta.env.VITE_BACKEND_URL;
  const headers = { Authorization: `Bearer ${apiKey}` };

  useEffect(() => {
    const fetchFilters = async () => {
      try {
        const orgRes = await axios.get(`${baseURL}/organizations`, { headers });
        const orgs = (orgRes.data?.data || []).map((o: any) => ({ id: o.id, name: o.name }));
        setOrganizations(orgs);
      } catch {}
    };
    fetchFilters();
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const params: any = {};
        if (filters.organizationId) params.organization_id = filters.organizationId;
        if (filters.agentId) params.agent_id = filters.agentId;

        const [agentsRes, metricsRes, llmUsageRes] = await Promise.all([
          axios.get(`${baseURL}/agents/operations/overview`, { headers, params }),
          axios.get(`${baseURL}/metrics/overview`, { headers }),
          axios.get(`${baseURL}/llm-usage/aggregated`, { headers, params: { ...params, timeframe: '24h' } })
        ]);

        // Load agents for Agent selector
        const activeAgents = agentsRes.data.data.active_agents || [];
        setAgents(activeAgents);

        // Organizations list already loaded; optional: load org-scoped if needed

        const successRateMetric = Array.isArray(metricsRes.data) ? 
          metricsRes.data.find((m: any) => m.success_rate_percent !== undefined) : null;
        const responseTimeMetric = Array.isArray(metricsRes.data) ? 
          metricsRes.data.find((m: any) => m.avg_response_time_ms !== undefined) : null;

        setDashboardData({
          agents: {
            active: activeAgents.length,
            total: activeAgents.length,
            successRate: successRateMetric ? parseFloat(successRateMetric.success_rate_percent) || 0 : 100,
            avgResponseTime: responseTimeMetric ? parseFloat(responseTimeMetric.avg_response_time_ms) / 1000 || 1.2 : 1.2
          },
          security: { threats: 0, riskLevel: "Low", complianceScore: 100 },
          costs: {
            totalTokens: (llmUsageRes.data.summary?.total_input_tokens || 0) + (llmUsageRes.data.summary?.total_output_tokens || 0),
            monthlyCost: llmUsageRes.data.summary?.total_cost || 0,
            costPerAgent: activeAgents.length > 0 ? (llmUsageRes.data.summary?.total_cost || 0) / activeAgents.length : 0
          },
          system: { cpu: Math.floor(Math.random() * 30) + 50, memory: Math.floor(Math.random() * 30) + 60, uptime: 99.9 }
        });

        // Format recent activity
        const activityData = agentsRes.data.data.recent_activity || [];
        const formattedActivity = activityData.map((activity: any) => {
          const date = new Date(activity.timestamp);
          const now = new Date();
          const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
          let timeString;
          if (diffInMinutes < 1) timeString = 'Just now';
          else if (diffInMinutes < 60) timeString = `${diffInMinutes} min ago`;
          else if (diffInMinutes < 1440) timeString = `${Math.floor(diffInMinutes / 60)} hours ago`;
          else timeString = `${Math.floor(diffInMinutes / 1440)} days ago`;
          return { time: timeString, event: activity.activity_type, status: activity.activity_type.toLowerCase().includes('failed') ? 'warning' : 'success' };
        });
        setRecentActivity(formattedActivity);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [filters.organizationId, filters.agentId]);

  const handleClearFilters = () => setFilters({});

  const getOrganizationName = (organizationId?: string) => {
    if (!organizationId) return 'N/A';
    const org = organizations.find(o => o.id === organizationId);
    return org?.name || 'N/A';
  };

  return (
    <div className="min-h-screen bg-background relative">
      <LineBackground />
      {/* Header */}
      <header className="border-b bg-card/95 backdrop-blur-sm relative z-10">
        <div className="flex h-16 items-center justify-between px-3 sm:px-6">
          <div className="flex items-center space-x-2 sm:space-x-4">
            <h1 className="text-lg sm:text-2xl font-bold">Analytics Dashboard</h1>
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              className="p-2"
            >
              {theme === "light" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="sm" className="hidden sm:flex" onClick={() => navigate('/agent-setup')}>
              <Plus className="mr-2 h-4 w-4" />
              Add Agent
            </Button>
            <Button variant="outline" size="sm" className="hidden sm:flex" onClick={() => navigate('/organization-setup')}>
              <Plus className="mr-2 h-4 w-4" />
              Add Organisation
            </Button>
            <Button variant="ghost" size="sm">
              <Settings className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      {/* Filters bar */}
      <div className="px-3 sm:px-6 py-3 flex flex-col sm:flex-row sm:items-center sm:space-x-3 space-y-2 sm:space-y-0">
        <Button variant="outline" onClick={handleClearFilters}>All Organizations</Button>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">Organization</span>
          <Select value={filters.organizationId || ''} onValueChange={(v) => setFilters({ organizationId: v || undefined, agentId: undefined })}>
            <SelectTrigger className="h-9 w-[220px]">
              <SelectValue placeholder="Select organization" />
            </SelectTrigger>
            <SelectContent>
              {organizations.map(org => (
                <SelectItem key={org.id} value={org.id}>{org.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">Agent</span>
          <Select value={filters.agentId || ''} onValueChange={(v) => setFilters(prev => ({ ...prev, agentId: v || undefined }))}>
            <SelectTrigger className="h-9 w-[220px]">
              <SelectValue placeholder="Select agent" />
            </SelectTrigger>
            <SelectContent>
              {agents.map((agent: any) => (
                <SelectItem key={agent.agent_id} value={agent.agent_id}>{agent.metadata?.name || agent.agent_id}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-3 sm:p-6 relative z-10">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4 sm:space-y-6">
          <div className="overflow-x-auto">
            <TabsList className="grid grid-cols-6 min-w-[500px] sm:min-w-0 sm:w-full">
              <TabsTrigger value="overview" className="text-xs sm:text-sm">Overview</TabsTrigger>
              <TabsTrigger value="agents" className="text-xs sm:text-sm">Agents</TabsTrigger>
              <TabsTrigger value="security" className="text-xs sm:text-sm">Security</TabsTrigger>
              <TabsTrigger value="costs" className="text-xs sm:text-sm">Costs</TabsTrigger>
              <TabsTrigger value="resources" className="text-xs sm:text-sm">Resources</TabsTrigger>
              <TabsTrigger value="operations" className="text-xs sm:text-sm">Operations</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="overview" className="space-y-4 sm:space-y-6">
            {/* Key Metrics Grid */}
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
              <Card className="animate-fade-in">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
                  <Users className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.agents.active}</div>
                  <p className="text-xs text-muted-foreground">
                    of {dashboardData.agents.total} total agents
                  </p>
                  <Progress value={(dashboardData.agents.active / Math.max(dashboardData.agents.total, 1)) * 100} className="mt-2" />
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.1s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.agents.successRate.toFixed(1)}%</div>
                  <p className="text-xs text-success">Based on last 24h</p>
                  <Progress value={dashboardData.agents.successRate} className="mt-2" />
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.2s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Monthly Cost</CardTitle>
                  <DollarSign className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${dashboardData.costs.monthlyCost.toFixed(2)}</div>
                  <p className="text-xs text-muted-foreground">
                    ${dashboardData.costs.costPerAgent.toFixed(2)}/agent
                  </p>
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.3s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">System Health</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.system.uptime}%</div>
                  <p className="text-xs text-success">Excellent uptime</p>
                  <div className="mt-2 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span>CPU</span>
                      <span>{dashboardData.system.cpu}%</span>
                    </div>
                    <Progress value={dashboardData.system.cpu} className="h-1" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Charts Row */}
            <div className="grid gap-4 sm:gap-6 grid-cols-1 lg:grid-cols-2">
              <Card className="animate-fade-in" style={{ animationDelay: "0.4s" }}>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <TrendingUp className="mr-2 h-5 w-5" />
                    Agent Performance
                  </CardTitle>
                  <CardDescription>Success rates and response times over 24 hours</CardDescription>
                </CardHeader>
                <CardContent>
                  <PerformanceChart />
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.5s" }}>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <DollarSign className="mr-2 h-5 w-5" />
                    Cost Breakdown
                  </CardTitle>
                  <CardDescription>Monthly spending analysis by category</CardDescription>
                </CardHeader>
                <CardContent>
                  <CostBreakdownChart />
                </CardContent>
              </Card>
            </div>

            {/* System Health Chart */}
            <Card className="animate-fade-in" style={{ animationDelay: "0.6s" }}>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Server className="mr-2 h-5 w-5" />
                  System Health Overview
                </CardTitle>
                <CardDescription>Real-time resource utilization monitoring</CardDescription>
              </CardHeader>
              <CardContent>
                <SystemHealthChart />
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card className="animate-fade-in" style={{ animationDelay: "0.6s" }}>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Latest agent operations and events</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentActivity.length > 0 ? recentActivity.map((activity, index) => (
                    <div key={index} className="flex items-center space-x-4 p-2 rounded-lg hover:bg-muted/50 transition-colors">
                      <div className={`w-2 h-2 rounded-full ${
                        activity.status === 'success' ? 'bg-success' :
                        activity.status === 'warning' ? 'bg-warning' :
                        'bg-info'
                      }`} />
                      <div className="flex-1">
                        <p className="text-sm">{activity.event}</p>
                        <p className="text-xs text-muted-foreground">{activity.time}</p>
                      </div>
                    </div>
                  )) : (
                    <div className="text-center text-muted-foreground py-4">
                      No recent activity
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Agents Tab */}
          <TabsContent value="agents" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Users className="mr-2 h-5 w-5" />
                    Agent Performance Metrics
                  </CardTitle>
                  <CardDescription>Individual agent success rates and response times</CardDescription>
                </CardHeader>
                <CardContent>
                  <PerformanceChart />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <BarChart3 className="mr-2 h-5 w-5" />
                    Agent Activity
                  </CardTitle>
                  <CardDescription>Sessions handled by each agent</CardDescription>
                </CardHeader>
                <CardContent>
                  <AgentActivityChart />
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 sm:gap-6 grid-cols-1 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Users className="mr-2 h-5 w-5" />
                    Agents List
                  </CardTitle>
                  <CardDescription>All active agents with their use cases and organizations</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {agents.length > 0 ? agents.map((agent: any, index: number) => (
                      <div key={index} className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <div className={`w-3 h-3 rounded-full ${
                              agent.status === 'active' ? 'bg-success' :
                              agent.status === 'idle' ? 'bg-warning' : 'bg-destructive'
                            }`} />
                            <span className="font-medium">{agent.name || agent.metadata?.name || 'Unnamed Agent'}</span>
                            <Badge variant="outline">{agent.status}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground">ID: {agent.agent_id}</p>
                          <p className="text-xs text-muted-foreground">Use Case: {agent.metadata?.useCase || 'N/A'}</p>
                          <p className="text-xs text-muted-foreground">Organization: {getOrganizationName(agent.organization_id)}</p>
                        </div>
                        <div className="text-right text-sm">
                          <p className="font-medium">0 sessions</p>
                          <p className="text-muted-foreground">SDK v{agent.sdk_version || '1.0.0'}</p>
                        </div>
                      </div>
                    )) : (
                      <div className="text-center text-muted-foreground py-4">
                        No agents found
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5" />
                    Organizations List
                  </CardTitle>
                  <CardDescription>Organizations using the platform with their agent counts</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {organizations.map((org, index) => (
                      <div key={index} className="p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-medium">{org.name}</h4>
                          <Badge variant="outline">Active</Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-muted-foreground">Agents</p>
                            <p className="font-medium">{(org as any).agent_count ?? '-'}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Sessions</p>
                            <p className="font-medium">{(org as any).total_sessions ?? '-'}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Monthly Usage</p>
                            <p className="font-medium text-success">${(org as any).monthly_usage ?? ''}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Status</p>
                            <p className="font-medium text-success">Active</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Activity className="mr-2 h-5 w-5" />
                  Conversation Quality Metrics
                </CardTitle>
                <CardDescription>Quality scores and failed session analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                  {[
                    { label: "Average Quality Score", value: "4.7/5", change: "+0.3", positive: true },
                    { label: "Failed Sessions", value: "3.2%", change: "-1.1%", positive: true },
                    { label: "Resolution Rate", value: `${dashboardData.agents.successRate.toFixed(1)}%`, change: "+2.3%", positive: true }
                  ].map((metric, index) => (
                    <div key={index} className="text-center p-4 border rounded-lg">
                      <p className="text-2xl font-bold">{metric.value}</p>
                      <p className="text-sm text-muted-foreground">{metric.label}</p>
                      <p className={`text-xs ${metric.positive ? 'text-success' : 'text-destructive'}`}>
                        {metric.change} from last week
                      </p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>


          {/* Security Tab */}
          <TabsContent value="security" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Risk Assessment Level</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-warning">{dashboardData.security.riskLevel}</div>
                  <p className="text-xs text-muted-foreground">{dashboardData.security.threats} active threats detected</p>
                  <Badge variant="outline" className="mt-2 text-warning">Monitoring Active</Badge>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Security Score</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-success">{dashboardData.security.complianceScore}%</div>
                  <p className="text-xs text-muted-foreground">Excellent security posture</p>
                  <Progress value={dashboardData.security.complianceScore} className="mt-2" />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Compliance Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-success">Compliant</div>
                  <p className="text-xs text-muted-foreground">All checks passed</p>
                  <Badge variant="outline" className="mt-2 text-success">GDPR ✓ CCPA ✓</Badge>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="mr-2 h-5 w-5" />
                  Security & Compliance Analytics
                </CardTitle>
                <CardDescription>Threat detection, PII monitoring, and compliance violations</CardDescription>
              </CardHeader>
              <CardContent>
                <SecurityChart />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Costs Tab */}
          <TabsContent value="costs" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Total Tokens Used</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.costs.totalTokens.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground">This month</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Monthly Cost</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${dashboardData.costs.monthlyCost.toFixed(2)}</div>
                  <p className="text-xs text-success">-8.2% from last month</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Cost per Agent</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${dashboardData.costs.costPerAgent.toFixed(2)}</div>
                  <p className="text-xs text-muted-foreground">Average monthly</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Usage Trend</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-success">↗ 12%</div>
                  <p className="text-xs text-muted-foreground">Compared to last month</p>
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 sm:gap-6 grid-cols-1 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <PieChart className="mr-2 h-5 w-5" />
                    Cost Breakdown
                  </CardTitle>
                  <CardDescription>Monthly spending by category</CardDescription>
                </CardHeader>
                <CardContent>
                  <CostBreakdownChart />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Clock className="mr-2 h-5 w-5" />
                    Session Duration Analytics
                  </CardTitle>
                  <CardDescription>Average session duration trends</CardDescription>
                </CardHeader>
                <CardContent>
                  <SessionDurationChart />
                </CardContent>
              </Card>
            </div>

            {/* LLM Usage History */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <BarChart3 className="mr-2 h-5 w-5" />
                  LLM Usage History
                </CardTitle>
                <CardDescription>Token consumption and model usage patterns over time</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
                    <div className="text-center p-4 border rounded-lg">
                      <p className="text-2xl font-bold">GPT-4</p>
                      <p className="text-sm text-muted-foreground">1.2M tokens</p>
                      <p className="text-xs text-success">$420.50</p>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                      <p className="text-2xl font-bold">GPT-3.5</p>
                      <p className="text-sm text-muted-foreground">890K tokens</p>
                      <p className="text-xs text-success">$178.20</p>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                      <p className="text-2xl font-bold">Claude</p>
                      <p className="text-sm text-muted-foreground">650K tokens</p>
                      <p className="text-xs text-success">$325.80</p>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                      <p className="text-2xl font-bold">Gemini</p>
                      <p className="text-sm text-muted-foreground">420K tokens</p>
                      <p className="text-xs text-success">$156.30</p>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <h4 className="text-sm font-medium">Recent Usage (Last 7 days)</h4>
                    {[
                      { date: "Today", model: "GPT-4", tokens: "45,230", cost: "$15.82", agent: "AI-001" },
                      { date: "Yesterday", model: "Claude", tokens: "32,100", cost: "$16.05", agent: "AI-003" },
                      { date: "2 days ago", model: "GPT-3.5", tokens: "67,450", cost: "$13.49", agent: "AI-002" },
                      { date: "3 days ago", model: "Gemini", tokens: "28,900", cost: "$10.74", agent: "AI-001" },
                      { date: "4 days ago", model: "GPT-4", tokens: "51,200", cost: "$17.92", agent: "AI-005" }
                    ].map((usage, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex items-center space-x-4">
                          <div className="text-sm font-medium">{usage.date}</div>
                          <Badge variant="outline">{usage.model}</Badge>
                          <div className="text-sm text-muted-foreground">{usage.agent}</div>
                        </div>
                        <div className="flex items-center space-x-4 text-sm">
                          <span>{usage.tokens} tokens</span>
                          <span className="font-medium">{usage.cost}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Resources Tab */}
          <TabsContent value="resources" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">CPU Usage</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.system.cpu}%</div>
                  <p className="text-xs text-muted-foreground">8 cores, 3.2 GHz average</p>
                  <Progress value={dashboardData.system.cpu} className="mt-2" />
                  <div className="mt-2 text-xs text-warning">
                    Peak: 89% (2:30 PM)
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Memory Usage</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{dashboardData.system.memory}%</div>
                  <p className="text-xs text-muted-foreground">13.6 GB used of 20 GB</p>
                  <Progress value={dashboardData.system.memory} className="mt-2" />
                  <div className="mt-2 text-xs text-success">
                    Available: 6.4 GB
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Storage Usage</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">45%</div>
                  <p className="text-xs text-muted-foreground">2.3 TB used of 5 TB</p>
                  <Progress value={45} className="mt-2" />
                  <div className="mt-2 text-xs text-info">
                    Growth: +120 GB this week
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Server className="mr-2 h-5 w-5" />
                  Resource Utilization Trends
                </CardTitle>
                <CardDescription>Real-time and historical resource usage patterns</CardDescription>
              </CardHeader>
              <CardContent>
                <SystemHealthChart />
              </CardContent>
            </Card>

            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Network I/O</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Inbound</span>
                      <span className="text-sm font-medium">245 MB/s</span>
                    </div>
                    <Progress value={62} className="h-2" />
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Outbound</span>
                      <span className="text-sm font-medium">189 MB/s</span>
                    </div>
                    <Progress value={47} className="h-2" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Performance Metrics</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Response Time</span>
                      <Badge variant="outline" className="text-success">Good</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Throughput</span>
                      <Badge variant="outline" className="text-success">Optimal</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Error Rate</span>
                      <Badge variant="outline" className="text-success">Low</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Queue Length</span>
                      <Badge variant="outline" className="text-warning">Moderate</Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Resource Alerts</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 rounded-full bg-warning" />
                      <span className="text-sm">High CPU usage detected</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 rounded-full bg-info" />
                      <span className="text-sm">Memory cleanup scheduled</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 rounded-full bg-success" />
                      <span className="text-sm">All systems operational</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Operations Tab */}
          <TabsContent value="operations" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5" />
                    Active Agents Overview
                  </CardTitle>
                  <CardDescription>Current agent status and recent activity</CardDescription>
                </CardHeader>
                <CardContent>
                  <AgentActivityChart />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Eye className="mr-2 h-5 w-5" />
                    Agent Status Monitor
                  </CardTitle>
                  <CardDescription>Real-time agent health and performance</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {agents.length > 0 ? agents.slice(0, 5).map((agent, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${
                            agent.status === 'active' ? 'bg-success' :
                            agent.status === 'idle' ? 'bg-warning' :
                            'bg-destructive'
                          }`} />
                          <span className="font-medium">{agent.agent_id}</span>
                        </div>
                        <div className="flex space-x-4 text-sm text-muted-foreground">
                          <span>0 sessions</span>
                          <span>100% uptime</span>
                        </div>
                      </div>
                    )) : (
                      Array.from({ length: 5 }, (_, index) => (
                        <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                          <div className="flex items-center space-x-3">
                            <div className="w-3 h-3 rounded-full bg-muted" />
                            <span className="font-medium text-muted-foreground">No agents</span>
                          </div>
                          <div className="flex space-x-4 text-sm text-muted-foreground">
                            <span>0 sessions</span>
                            <span>0% uptime</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Recent Operations</CardTitle>
                <CardDescription>Latest agent operations and system events</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentActivity.length > 0 ? recentActivity.map((operation, index) => (
                    <div key={index} className="flex items-center space-x-4 p-2 rounded-lg hover:bg-muted/50 transition-colors">
                      <div className={`w-2 h-2 rounded-full ${
                        operation.status === 'success' ? 'bg-success' :
                        operation.status === 'warning' ? 'bg-warning' :
                        'bg-info'
                      }`} />
                      <div className="flex-1">
                        <p className="text-sm">{operation.event}</p>
                        <p className="text-xs text-muted-foreground">{operation.time}</p>
                      </div>
                    </div>
                  )) : (
                    Array.from({ length: 5 }, (_, index) => (
                      <div key={index} className="flex items-center space-x-4 p-2 rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="w-2 h-2 rounded-full bg-info" />
                        <div className="flex-1">
                          <p className="text-sm">System monitoring active</p>
                          <p className="text-xs text-muted-foreground">Continuous</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Dashboard;