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
import LineBackground from "@/components/LineBackground";
import { useTheme } from "@/components/ThemeProvider";
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
  PieChart,
  Sun,
  Moon
} from "lucide-react";

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { theme, setTheme } = useTheme();

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
            <Button variant="outline" size="sm" className="hidden sm:flex">
              <Plus className="mr-2 h-4 w-4" />
              Add Agent
            </Button>
            <Button variant="outline" size="sm" className="hidden sm:flex">
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
                    {[
                      { 
                        id: "AI-001", 
                        name: "Customer Support Agent", 
                        useCase: "Customer Service", 
                        org: "TechCorp Inc", 
                        status: "active",
                        sessions: 142,
                        uptime: "99.9%"
                      },
                      { 
                        id: "AI-002", 
                        name: "Sales Assistant", 
                        useCase: "Lead Qualification", 
                        org: "SalesForce Ltd", 
                        status: "active",
                        sessions: 98,
                        uptime: "99.7%"
                      },
                      { 
                        id: "AI-003", 
                        name: "Technical Support", 
                        useCase: "IT Helpdesk", 
                        org: "TechCorp Inc", 
                        status: "idle",
                        sessions: 67,
                        uptime: "100%"
                      },
                      { 
                        id: "AI-004", 
                        name: "HR Assistant", 
                        useCase: "Employee Onboarding", 
                        org: "HR Solutions", 
                        status: "maintenance",
                        sessions: 0,
                        uptime: "0%"
                      },
                      { 
                        id: "AI-005", 
                        name: "Marketing Bot", 
                        useCase: "Content Generation", 
                        org: "MarketingPro", 
                        status: "active",
                        sessions: 156,
                        uptime: "99.8%"
                      }
                    ].map((agent, index) => (
                      <div key={index} className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <div className={`w-3 h-3 rounded-full ${
                              agent.status === 'active' ? 'bg-success' :
                              agent.status === 'idle' ? 'bg-warning' :
                              'bg-destructive'
                            }`} />
                            <span className="font-medium">{agent.id}</span>
                            <Badge variant="outline">{agent.status}</Badge>
                          </div>
                          <p className="text-sm font-medium">{agent.name}</p>
                          <p className="text-xs text-muted-foreground">Use Case: {agent.useCase}</p>
                          <p className="text-xs text-muted-foreground">Organization: {agent.org}</p>
                        </div>
                        <div className="text-right text-sm">
                          <p className="font-medium">{agent.sessions} sessions</p>
                          <p className="text-muted-foreground">{agent.uptime} uptime</p>
                        </div>
                      </div>
                    ))}
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
                    {[
                      { 
                        name: "TechCorp Inc", 
                        agentCount: 2, 
                        plan: "Enterprise", 
                        totalSessions: 209,
                        monthlyUsage: "$1,250"
                      },
                      { 
                        name: "SalesForce Ltd", 
                        agentCount: 1, 
                        plan: "Professional", 
                        totalSessions: 98,
                        monthlyUsage: "$420"
                      },
                      { 
                        name: "HR Solutions", 
                        agentCount: 1, 
                        plan: "Basic", 
                        totalSessions: 0,
                        monthlyUsage: "$150"
                      },
                      { 
                        name: "MarketingPro", 
                        agentCount: 1, 
                        plan: "Professional", 
                        totalSessions: 156,
                        monthlyUsage: "$680"
                      }
                    ].map((org, index) => (
                      <div key={index} className="p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-medium">{org.name}</h4>
                          <Badge variant="outline">{org.plan}</Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-muted-foreground">Agents</p>
                            <p className="font-medium">{org.agentCount}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Sessions</p>
                            <p className="font-medium">{org.totalSessions}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Monthly Usage</p>
                            <p className="font-medium text-success">{org.monthlyUsage}</p>
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


          {/* Security Tab */}
          <TabsContent value="security" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
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
          <TabsContent value="costs" className="space-y-4 sm:space-y-6">
            <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
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
                  <div className="text-2xl font-bold">72%</div>
                  <p className="text-xs text-muted-foreground">8 cores, 3.2 GHz average</p>
                  <Progress value={72} className="mt-2" />
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
                  <div className="text-2xl font-bold">68%</div>
                  <p className="text-xs text-muted-foreground">13.6 GB used of 20 GB</p>
                  <Progress value={68} className="mt-2" />
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