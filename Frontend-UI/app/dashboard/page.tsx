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
import { useState } from "react"

export default function DashboardPage() {
  const { organizations, currentOrganization, setCurrentOrganization, getAgentsByOrganization, removeAgent } =
    useAgent()
  const router = useRouter()
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)

  const currentAgents = currentOrganization ? getAgentsByOrganization(currentOrganization.id) : []
  const selectedAgentData = selectedAgent ? currentAgents.find((agent) => agent.id === selectedAgent) : null

  // Show zeros immediately - no API calls needed
  const displayMetrics = {
    performance: "0%",
    security: "0%", 
    cost: "$0.00",
    quality: "0/5",
  }

  // Analytics cards with zero values
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

  // Empty recent activity
  const recentActivity: any[] = []

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
            <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          </div>
          <p className="text-muted-foreground">
            {selectedAgentData 
              ? `Monitoring ${selectedAgentData.name} agent performance`
              : "Monitor and manage your AI agents across organizations"
            }
          </p>
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

      {!currentOrganization && organizations.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Building2 className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No Organizations</h3>
            <p className="text-muted-foreground text-center mb-4">
              Create your first organization to start managing AI agents
            </p>
            <Button onClick={handleAddOrganization}>
              <Plus className="h-4 w-4 mr-2" />
              Create Organization
            </Button>
          </CardContent>
        </Card>
      )}

      {currentOrganization && currentAgents.length === 0 && (
        <div className="text-center py-8">
          <h2 className="text-xl font-semibold text-muted-foreground mb-2">Organization Overview</h2>
          <p className="text-muted-foreground mb-4">Average metrics across 0 agents</p>
          <Button onClick={handleAddAgent}>
            <Plus className="h-4 w-4 mr-2" />
            Add Your First Agent
          </Button>
        </div>
      )}

      {currentOrganization && (
        <>
          {/* Analytics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {analyticsCardsData.map((metric) => {
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
            })}
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
                              <div className="absolute inset-0 h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
                            )}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center space-x-2">
                              <span className="font-medium">{agent.name}</span>
                              <Badge variant="outline" className="text-xs">
                                {agent.provider}
                              </Badge>
                              <Badge variant="secondary" className="text-xs">
                                {agent.model}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{agent.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-4">
                          <div className="text-center">
                            <div className="text-sm font-medium">0%</div>
                            <div className="text-xs text-muted-foreground">Performance</div>
                          </div>
                          <div className="text-center">
                            <div className="text-sm font-medium">$0</div>
                            <div className="text-xs text-muted-foreground">Cost</div>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleDeleteAgent(agent.id)
                            }}
                            className={`h-8 w-8 p-0 ${
                              deleteConfirm === agent.id ? "text-red-600 bg-red-50" : ""
                            }`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    )
                  })
                ) : (
                  <div className="text-center py-8">
                    <Bot className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">No agents connected</p>
                    <p className="text-xs text-muted-foreground mt-1">Add your first agent to get started</p>
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
                {recentActivity.length > 0 ? (
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
        </>
      )}
    </div>
  )
}
