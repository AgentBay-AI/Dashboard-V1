import { useState } from "react";
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
import { 
  Activity, 
  Users, 
  Shield, 
  DollarSign, 
  Clock, 
  Cpu, 
  Plus,
  Settings,
  TrendingUp,
  AlertTriangle,
  Eye,
  Server,
  Zap,
  BarChart3,
  PieChart
} from "lucide-react";

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");

  const mockData = {
    agents: {
      active: 12,
      total: 25,
      successRate: 94.2,
      avgResponseTime: 1.2
    },
    security: {
      threats: 3,
      riskLevel: "Medium",
      complianceScore: 96
    },
    costs: {
      totalTokens: 2456780,
      monthlyCost: 1247.50,
      costPerAgent: 49.90
    },
    system: {
      cpu: 68,
      memory: 74,
      uptime: 99.9
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="flex h-16 items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <h1 className="text-2xl font-bold">Analytics Dashboard</h1>
          </div>
          <div className="flex items-center space-x-4">
            <Button variant="outline" size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Add Agent
            </Button>
            <Button variant="outline" size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Add Organisation
            </Button>
            <Button variant="ghost" size="sm">
              <Settings className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-7">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="agents">Agents</TabsTrigger>
            <TabsTrigger value="system">System</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="costs">Costs</TabsTrigger>
            <TabsTrigger value="resources">Resources</TabsTrigger>
            <TabsTrigger value="operations">Operations</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            {/* Key Metrics Grid */}
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              <Card className="animate-fade-in">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
                  <Users className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{mockData.agents.active}</div>
                  <p className="text-xs text-muted-foreground">
                    of {mockData.agents.total} total agents
                  </p>
                  <Progress value={(mockData.agents.active / mockData.agents.total) * 100} className="mt-2" />
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.1s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{mockData.agents.successRate}%</div>
                  <p className="text-xs text-success">+2.3% from last week</p>
                  <Progress value={mockData.agents.successRate} className="mt-2" />
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.2s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Monthly Cost</CardTitle>
                  <DollarSign className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${mockData.costs.monthlyCost}</div>
                  <p className="text-xs text-muted-foreground">
                    ${mockData.costs.costPerAgent}/agent
                  </p>
                </CardContent>
              </Card>

              <Card className="animate-fade-in" style={{ animationDelay: "0.3s" }}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">System Health</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{mockData.system.uptime}%</div>
                  <p className="text-xs text-success">Excellent uptime</p>
                  <div className="mt-2 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span>CPU</span>
                      <span>{mockData.system.cpu}%</span>
                    </div>
                    <Progress value={mockData.system.cpu} className="h-1" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Charts Row */}
            <div className="grid gap-6 md:grid-cols-2">
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
                  {[
                    { time: "2 min ago", event: "Agent AI-001 completed session", status: "success" },
                    { time: "5 min ago", event: "New security threat detected", status: "warning" },
                    { time: "12 min ago", event: "Agent AI-007 started session", status: "info" },
                    { time: "18 min ago", event: "System backup completed", status: "success" }
                  ].map((activity, index) => (
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
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Agents Tab */}
          <TabsContent value="agents" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
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

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Activity className="mr-2 h-5 w-5" />
                  Conversation Quality Metrics
                </CardTitle>
                <CardDescription>Quality scores and failed session analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-3">
                  {[
                    { label: "Average Quality Score", value: "4.7/5", change: "+0.3", positive: true },
                    { label: "Failed Sessions", value: "3.2%", change: "-1.1%", positive: true },
                    { label: "Resolution Rate", value: "94.2%", change: "+2.3%", positive: true }
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

          {/* System Tab */}
          <TabsContent value="system" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              {[
                { title: "CPU Usage", value: `${mockData.system.cpu}%`, icon: Cpu, color: "text-chart-1" },
                { title: "Memory Usage", value: `${mockData.system.memory}%`, icon: Server, color: "text-chart-2" },
                { title: "System Uptime", value: `${mockData.system.uptime}%`, icon: Activity, color: "text-success" },
                { title: "Response Time", value: "1.2s", icon: Zap, color: "text-warning" }
              ].map((metric, index) => (
                <Card key={index}>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{metric.title}</CardTitle>
                    <metric.icon className={`h-4 w-4 ${metric.color}`} />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{metric.value}</div>
                    <Progress value={parseInt(metric.value)} className="mt-2" />
                  </CardContent>
                </Card>
              ))}
            </div>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Server className="mr-2 h-5 w-5" />
                  System Health Monitoring
                </CardTitle>
                <CardDescription>Real-time resource utilization and performance bottlenecks</CardDescription>
              </CardHeader>
              <CardContent>
                <SystemHealthChart />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Risk Assessment Level</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-warning">Medium</div>
                  <p className="text-xs text-muted-foreground">3 active threats detected</p>
                  <Badge variant="outline" className="mt-2 text-warning">Monitoring Active</Badge>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Security Score</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-success">96%</div>
                  <p className="text-xs text-muted-foreground">Excellent security posture</p>
                  <Progress value={96} className="mt-2" />
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
          <TabsContent value="costs" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Total Tokens Used</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{mockData.costs.totalTokens.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground">This month</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Monthly Cost</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${mockData.costs.monthlyCost}</div>
                  <p className="text-xs text-success">-8.2% from last month</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Cost per Agent</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${mockData.costs.costPerAgent}</div>
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

            <div className="grid gap-6 md:grid-cols-2">
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
          </TabsContent>

          {/* Resources Tab */}
          <TabsContent value="resources" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Server className="mr-2 h-5 w-5" />
                  Resource Utilization
                </CardTitle>
                <CardDescription>Real-time and historical resource usage patterns</CardDescription>
              </CardHeader>
              <CardContent>
                <SystemHealthChart />
              </CardContent>
            </Card>

            <div className="grid gap-6 md:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Performance Bottlenecks</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Database Queries</span>
                      <Badge variant="outline" className="text-warning">Moderate</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Memory Allocation</span>
                      <Badge variant="outline" className="text-success">Optimal</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Network Latency</span>
                      <Badge variant="outline" className="text-success">Good</Badge>
                    </div>
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
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Historical Trends</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-info">Stable</div>
                  <p className="text-xs text-muted-foreground">Resource usage patterns</p>
                  <Badge variant="outline" className="mt-2 text-info">No Anomalies</Badge>
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
                    {[
                      { agent: "AI-001", status: "active", sessions: 12, uptime: "99.9%" },
                      { agent: "AI-002", status: "active", sessions: 8, uptime: "99.7%" },
                      { agent: "AI-003", status: "idle", sessions: 0, uptime: "100%" },
                      { agent: "AI-004", status: "maintenance", sessions: 0, uptime: "0%" },
                      { agent: "AI-005", status: "active", sessions: 15, uptime: "99.8%" }
                    ].map((agent, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${
                            agent.status === 'active' ? 'bg-success' :
                            agent.status === 'idle' ? 'bg-warning' :
                            'bg-destructive'
                          }`} />
                          <span className="font-medium">{agent.agent}</span>
                        </div>
                        <div className="flex space-x-4 text-sm text-muted-foreground">
                          <span>{agent.sessions} sessions</span>
                          <span>{agent.uptime} uptime</span>
                        </div>
                      </div>
                    ))}
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
                  {[
                    { time: "2 min ago", operation: "Agent AI-001 completed session #4521", type: "success" },
                    { time: "5 min ago", operation: "Agent AI-003 entered idle state", type: "info" },
                    { time: "8 min ago", operation: "System backup initiated", type: "info" },
                    { time: "12 min ago", operation: "Agent AI-004 started maintenance mode", type: "warning" },
                    { time: "15 min ago", operation: "New agent AI-005 deployed successfully", type: "success" }
                  ].map((operation, index) => (
                    <div key={index} className="flex items-center space-x-4 p-2 rounded-lg hover:bg-muted/50 transition-colors">
                      <div className={`w-2 h-2 rounded-full ${
                        operation.type === 'success' ? 'bg-success' :
                        operation.type === 'warning' ? 'bg-warning' :
                        'bg-info'
                      }`} />
                      <div className="flex-1">
                        <p className="text-sm">{operation.operation}</p>
                        <p className="text-xs text-muted-foreground">{operation.time}</p>
                      </div>
                    </div>
                  ))}
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
