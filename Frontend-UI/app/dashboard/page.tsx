"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAgent } from "@/components/agent-provider"
import { useRouter } from "next/navigation"
import {
  Plus,
  Building2,
  Bot,
  Activity,
  TrendingUp,
  AlertTriangle,
  DollarSign,
  Zap,
  Shield,
  MessageSquare,
  Clock,
  Trash2,
  ArrowLeft,
  BarChart3,
} from "lucide-react"
import { PerformanceChart } from "@/components/dashboard/performance-chart"
import { ResourceUtilization } from "@/components/dashboard/resource-utilization"
import { BackendStatus } from "@/components/dashboard/backend-status"
import { useState, useEffect } from "react"

export default function DashboardPage() {
  const { organizations, currentOrganization, setCurrentOrganization, getAgentsByOrganization, removeAgent } =
    useAgent()
  const router = useRouter()
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)

  const currentAgents = currentOrganization ? getAgentsByOrganization(currentOrganization.id) : []
  const selectedAgentData = selectedAgent ? currentAgents.find((agent) => agent.id === selectedAgent) : null

  // Loading states for different components
  const [isLoading, setIsLoading] = useState(true)
  const [metricsLoading, setMetricsLoading] = useState(true)
  const [activityLoading, setActivityLoading] = useState(true)
  const [chartsLoading, setChartsLoading] = useState(true)

  // Real metrics from backend - show zeros immediately, update when data loads
  const [realMetrics, setRealMetrics] = useState({
    performance: "0%",
    security: "0%", 
    cost: "$0.00",
    quality: "0/5",
  })

  // Real analytics data
  const [analyticsData, setAnalyticsData] = useState<any[]>([])
  const [recentActivity, setRecentActivity] = useState<any[]>([])
  const [resourceData, setResourceData] = useState<any>({})

  // Cache to prevent duplicate requests
  const [lastFetchTime, setLastFetchTime] = useState<number>(0)
  const CACHE_DURATION = 30000 // 30 seconds

  // Optimized fetch function with immediate zeros display
  const fetchDashboardData = async (showLoading = true) => {
    const now = Date.now()
    
    // Skip if we fetched recently (cache)
    if (now - lastFetchTime < CACHE_DURATION && !showLoading) {
      return
    }

    try {
      if (showLoading) {
        setIsLoading(true)
        setMetricsLoading(true)
        setActivityLoading(true)
        setChartsLoading(true)
      }

      const backendUrl = 'http://localhost:8080'
      const agentId = selectedAgentData?.id

      // Batch API calls with shorter timeouts for speed
      const [performanceRes, resourceRes, costRes, activityRes] = await Promise.allSettled([
        fetch(`${backendUrl}/api/analytics/performance${agentId ? `?agent_id=${agentId}` : ''}`, {
          signal: AbortSignal.timeout(5000) // Reduced to 5 seconds
        }),
        fetch(`${backendUrl}/api/analytics/resource-utilization`, {
          signal: AbortSignal.timeout(5000)
        }),
        fetch(`${backendUrl}/api/analytics/cost-breakdown`, {
          signal: AbortSignal.timeout(5000)
        }),
        fetch(`${backendUrl}/api/analytics/activity?limit=5`, {
          signal: AbortSignal.timeout(5000)
        })
      ])

      // Process performance data with fallback to zeros
      if (performanceRes.status === 'fulfilled' && performanceRes.value.ok) {
        const perfData = await performanceRes.value.json()
        const avgPerformance = perfData.average_performance || 0
        const totalCost = perfData.total_cost || 0
        
        setRealMetrics({
          performance: `${avgPerformance}%`,
          security: "0%", // Keep as 0% until security endpoint is ready
          cost: `$${totalCost.toFixed(2)}`,
          quality: "0/5", // Keep as 0/5 until quality scoring is ready
        })

        setAnalyticsData(perfData.data || [])
      } else {
        // Keep zeros - don't change from initial state
        console.log('Analytics API not responding, keeping zero state')
      }
      setMetricsLoading(false)
      setChartsLoading(false)

      // Process resource utilization
      if (resourceRes.status === 'fulfilled' && resourceRes.value.ok) {
        const resourceResponse = await resourceRes.value.json()
        setResourceData(resourceResponse.data || {})
      }

      // Process recent activity
      if (activityRes.status === 'fulfilled' && activityRes.value.ok) {
        const activityData = await activityRes.value.json()
        const activities = (activityData.activities || []).map((activity: any) => ({
          id: activity.id,
          type: activity.type || 'info',
          title: `${activity.agent_name || 'System'}: ${activity.type || 'Update'}`,
          description: activity.message || 'No description available',
          time: new Date(activity.timestamp).toLocaleString(),
          icon: activity.type === 'error' ? AlertTriangle : Activity,
          color: activity.severity === 'critical' ? 'text-red-600' : 
                 activity.severity === 'high' ? 'text-orange-600' :
                 activity.severity === 'medium' ? 'text-amber-600' : 'text-blue-600'
        }))
        setRecentActivity(activities)
      }
      setActivityLoading(false)

      setLastFetchTime(now)
      console.log('✅ Dashboard data refreshed')
    } catch (error) {
      console.error('❌ Failed to fetch dashboard data:', error)
      
      // Keep zeros instead of showing error
      setMetricsLoading(false)
      setActivityLoading(false)
      setChartsLoading(false)
    } finally {
      setIsLoading(false)
    }
  }

  // Fast initial load - no debounce, immediate display
  useEffect(() => {
    fetchDashboardData(false) // Don't show loading on initial load
  }, [selectedAgentData?.id])

  // Reduced auto-refresh for better performance
  useEffect(() => {
    const interval = setInterval(() => {
      if (!isLoading && !metricsLoading) {
        fetchDashboardData(false) // Silent refresh
      }
    }, 120000) // Increased to 2 minutes for better performance

    return () => clearInterval(interval)
  }, [isLoading, metricsLoading, lastFetchTime])

  const displayMetrics = realMetrics

  // Create analytics cards data with zero values by default
  const analyticsCardsData = [
    {
      id: "performance", 
      title: "Performance Score", 
      value: displayMetrics.performance, 
      change: "0%", 
      trend: "up" as const, 
      icon: Zap, 
      color: "text-emerald-600 dark:text-emerald-400"
    },
    {
      id: "security", 
      title: "Security Rating", 
      value: displayMetrics.security, 
      change: "0%", 
      trend: "up" as const, 
      icon: Shield, 
      color: "text-blue-600 dark:text-blue-400"
    },
    {
      id: "cost", 
      title: selectedAgentData ? "Agent Cost" : "Avg Monthly Cost", 
      value: displayMetrics.cost, 
      change: "0%", 
      trend: "down" as const, 
      icon: DollarSign, 
      color: "text-violet-600 dark:text-violet-400"
    },
    {
      id: "conversation", 
      title: "Conversation Quality", 
      value: displayMetrics.quality, 
      change: "0%", 
      trend: "up" as const, 
      icon: MessageSquare, 
      color: "text-orange-600 dark:text-orange-400"
    },
  ]

  // Populate analytics data from real metrics when they change
  useEffect(() => {
    setAnalyticsData(analyticsCardsData)
  }, [displayMetrics, selectedAgentData])

  // Fetch recent activity from backend
  useEffect(() => {
    const fetchActivity = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/activity?limit=5')
        if (response.ok) {
          const result = await response.json()
          const activities = result.activities.map((activity: any) => ({
            id: activity.id,
            type: activity.type,
            title: `${activity.agent_name}: ${activity.type}`,
            description: activity.message,
            time: new Date(activity.timestamp).toLocaleString(),
            icon: activity.type === 'error' ? AlertTriangle : Activity,
            color: activity.severity === 'critical' ? 'text-red-600' : 
                   activity.severity === 'high' ? 'text-orange-600' :
                   activity.severity === 'medium' ? 'text-amber-600' : 'text-blue-600'
          }))
          setRecentActivity(activities)
        }
      } catch (error) {
        console.error('Failed to fetch activity:', error)
        // Keep empty activity list - no fallback data
        setRecentActivity([])
      }
    }

    fetchActivity()
  }, [currentOrganization])

  const handleDeleteAgent = (agentId: string) => {
    if (deleteConfirm === agentId) {
      removeAgent(agentId)
      setDeleteConfirm(null)
      if (selectedAgent === agentId) {
        setSelectedAgent(null)
      }
    } else {
      setDeleteConfirm(agentId)
      setTimeout(() => setDeleteConfirm(null), 3000)
    }
  }

  const handleAgentClick = (agentId: string) => {
    setSelectedAgent(agentId)
  }

  const handleBackToOverview = () => {
    setSelectedAgent(null)
  }

  const handleAddOrganization = () => {
    router.push("/setup?type=organization")
  }

  const handleAddAgent = () => {
    router.push("/setup?type=agent")
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            {selectedAgent && (
              <Button variant="ghost" size="sm" onClick={handleBackToOverview} className="h-8 w-8 p-0">
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">
                {selectedAgentData ? selectedAgentData.name : "Dashboard"}
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                {selectedAgentData
                  ? `Individual agent analysis for ${selectedAgentData.name}`
                  : "Monitor and manage your AI agents across organizations"}
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Select
            value={currentOrganization?.id || ""}
            onValueChange={(value) => {
              const org = organizations.find((o) => o.id === value)
              if (org) {
                setCurrentOrganization(org)
                setSelectedAgent(null)
              }
            }}
          >
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Select organization" />
            </SelectTrigger>
            <SelectContent>
              {organizations.map((org) => (
                <SelectItem key={org.id} value={org.id}>
                  {org.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button variant="outline" onClick={handleAddOrganization}>
            <Building2 className="h-4 w-4 mr-2" />
            New Organization
          </Button>

          <Button onClick={handleAddAgent}>
            <Plus className="h-4 w-4 mr-2" />
            Add Agent
          </Button>
        </div>
      </div>

      {/* Organization Overview */}
      {currentOrganization && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-lg font-medium">{currentOrganization.name}</CardTitle>
                <CardDescription className="capitalize">
                  {currentOrganization.industry} • {currentAgents.length} agents
                  {selectedAgentData && (
                    <span className="ml-2 text-blue-600 dark:text-blue-400">• Viewing: {selectedAgentData.name}</span>
                  )}
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Badge
                  variant="secondary"
                  className="bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-300 dark:border-emerald-800"
                >
                  Active
                </Badge>
                {selectedAgentData && (
                  <Badge
                    variant="outline"
                    className="bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/20 dark:text-blue-300 dark:border-blue-800"
                  >
                    Individual View
                  </Badge>
                )}
              </div>
            </div>
          </CardHeader>
        </Card>
      )}

      {/* Analytics Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{selectedAgentData ? "Agent Performance" : "Organization Overview"}</h2>
          <p className="text-sm text-muted-foreground">
            {selectedAgentData
              ? `Detailed metrics for ${selectedAgentData.name}`
              : `Average metrics across ${currentAgents.length} agents`}
          </p>
        </div>
        {selectedAgentData && (
          <Button variant="outline" onClick={handleBackToOverview} size="sm">
            <BarChart3 className="h-4 w-4 mr-2" />
            View All Agents
          </Button>
        )}
      </div>

      {/* Analytics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {metricsLoading ? (
          // Loading skeleton for metrics
          Array.from({ length: 4 }).map((_, index) => (
            <Card key={`loading-${index}`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="h-4 bg-muted rounded animate-pulse mb-2" />
                    <div className="h-6 bg-muted rounded animate-pulse w-20" />
                    <div className="h-3 bg-muted rounded animate-pulse w-16 mt-2" />
                  </div>
                  <div className="p-2 rounded-lg bg-muted/50 ml-3">
                    <div className="h-5 w-5 bg-muted rounded animate-pulse" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          analyticsCardsData.map((metric) => {
            const Icon = metric.icon
            return (
              <Card key={metric.id}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-muted-foreground mb-1">{metric.title}</p>
                      <p className="text-xl font-semibold">{metric.value}</p>
                      <p
                        className={`text-sm font-medium mt-1 ${
                          metric.trend === "up"
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-red-600 dark:text-red-400"
                        }`}
                      >
                        {metric.change}
                      </p>
                    </div>
                    <div className="p-2 rounded-lg bg-muted/50 ml-3">
                      <Icon className={`h-5 w-5 ${metric.color}`} />
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })
        )}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Connected Agents */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-lg font-medium">Connected Agents</CardTitle>
              <CardDescription>
                {currentAgents.length} agents in {currentOrganization?.name || "organization"}
                {selectedAgentData && " • Click any agent to view individual metrics"}
              </CardDescription>
            </div>
            <Button size="sm" onClick={handleAddAgent}>
              <Plus className="h-4 w-4 mr-2" />
              Add Agent
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {currentAgents.length > 0 ? (
                                currentAgents.map((agent) => {
                    // Use real agent metrics from backend data
                    const agentMetrics = {
                      performance: agent.performance || 0,
                      security: 0, // Will come from backend security data
                      cost: agent.cost || 0
                    }
                    const isSelected = selectedAgent === agent.id

                    return (
                  <div
                    key={agent.id}
                    className={`flex items-center justify-between p-3 border rounded-lg cursor-pointer transition-all hover:shadow-sm ${
                      isSelected
                        ? "border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20"
                        : "border-border hover:border-border/60"
                    }`}
                    onClick={() => handleAgentClick(agent.id)}
                  >
                    <div className="flex items-center space-x-3 flex-1">
                      <div className="relative">
                        <div
                          className={`h-2 w-2 rounded-full ${
                            agent.status === "active"
                              ? "bg-emerald-500"
                              : agent.status === "error"
                                ? "bg-red-500"
                                : "bg-muted-foreground"
                          }`}
                        />
                        {agent.status === "active" && (
                          <div className="absolute inset-0 h-2 w-2 rounded-full bg-emerald-500 animate-ping opacity-75" />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-sm">{agent.name}</p>
                            <p className="text-xs text-muted-foreground">{agent.description}</p>
                            {deleteConfirm === agent.id && (
                              <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                                Click delete again to confirm removal
                              </p>
                            )}
                            <div className="flex items-center space-x-2 text-xs text-muted-foreground mt-1">
                              <span className="capitalize">{agent.provider}</span>
                              <span>•</span>
                              <span className="capitalize">{agent.framework}</span>
                              <span>•</span>
                              <span>Last sync: 2 min ago</span>
                            </div>
                          </div>

                          {/* Agent Metrics */}
                          <div className="flex items-center space-x-4 text-xs">
                            <div className="text-center">
                              <p className="font-medium">{agentMetrics.performance}%</p>
                              <p className="text-muted-foreground">Performance</p>
                            </div>
                            <div className="text-center">
                              <p className="font-medium">{agentMetrics.security}%</p>
                              <p className="text-muted-foreground">Security</p>
                            </div>
                            <div className="text-center">
                              <p className="font-medium">${agentMetrics.cost}</p>
                              <p className="text-muted-foreground">Monthly</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-1 ml-3">
                      <Badge variant={agent.status === "active" ? "secondary" : "outline"} className="text-xs">
                        {agent.status}
                      </Badge>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                        }}
                        className="h-7 w-7 p-0"
                      >
                        <Activity className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleDeleteAgent(agent.id)
                        }}
                        className={`h-7 w-7 p-0 ${deleteConfirm === agent.id ? "text-red-600 dark:text-red-400" : ""}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="text-center py-8">
                <Bot className="h-8 w-8 mx-auto mb-3 text-muted-foreground" />
                <p className="text-muted-foreground mb-1">No agents connected</p>
                <p className="text-sm text-muted-foreground mb-3">Add your first AI agent to start monitoring</p>
                <Button onClick={handleAddAgent} size="sm">
                  <Plus className="h-4 w-4 mr-2" />
                  Add Agent
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg font-medium">Recent Activity</CardTitle>
            <CardDescription>
              {selectedAgentData ? `Activity for ${selectedAgentData.name}` : "Latest events and notifications"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {activityLoading ? (
              // Loading skeleton for activity
              Array.from({ length: 3 }).map((_, index) => (
                <div key={`activity-loading-${index}`} className="flex items-start space-x-3 p-2 rounded-lg">
                  <div className="p-1.5 rounded-lg bg-muted">
                    <div className="h-3 w-3 bg-muted-foreground/30 rounded animate-pulse" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="h-4 bg-muted rounded animate-pulse mb-1" />
                    <div className="h-3 bg-muted rounded animate-pulse w-3/4 mt-1" />
                    <div className="h-3 bg-muted rounded animate-pulse w-1/2 mt-1" />
                  </div>
                </div>
              ))
            ) : recentActivity.length > 0 ? (
              recentActivity.map((activity) => {
                const Icon = activity.icon
                return (
                  <div
                    key={activity.id}
                    className="flex items-start space-x-3 p-2 rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="p-1.5 rounded-lg bg-muted">
                      <Icon className={`h-3 w-3 ${activity.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-sm">{activity.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">{activity.description}</p>
                      <div className="flex items-center mt-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3 mr-1" />
                        {activity.time}
                      </div>
                    </div>
                  </div>
                )
              })
            ) : (
              // Empty state when no activity
              <div className="text-center py-6">
                <Activity className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No recent activity</p>
                <p className="text-xs text-muted-foreground mt-1">Agent activities will appear here</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Backend Status */}
      <BackendStatus />

      {/* Performance Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <PerformanceChart />
        <ResourceUtilization />
      </div>
    </div>
  )
}
