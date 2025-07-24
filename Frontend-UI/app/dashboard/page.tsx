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
import { useState } from "react"

export default function DashboardPage() {
  const { organizations, currentOrganization, setCurrentOrganization, getAgentsByOrganization, removeAgent } =
    useAgent()
  const router = useRouter()
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)

  const currentAgents = currentOrganization ? getAgentsByOrganization(currentOrganization.id) : []
  const selectedAgentData = selectedAgent ? currentAgents.find((agent) => agent.id === selectedAgent) : null

  // Mock individual agent metrics
  const getAgentMetrics = (agentId: string) => {
    const baseMetrics = {
      performance: Math.floor(Math.random() * 20) + 80, // 80-100%
      security: Math.floor(Math.random() * 10) + 90, // 90-100%
      cost: Math.floor(Math.random() * 500) + 100, // $100-600
      quality: (Math.random() * 1 + 4).toFixed(1), // 4.0-5.0
    }
    return baseMetrics
  }

  // Calculate average metrics for all agents
  const getAverageMetrics = () => {
    if (currentAgents.length === 0) {
      return {
        performance: "0%",
        security: "0%",
        cost: "$0",
        quality: "0/5",
      }
    }

    const totalMetrics = currentAgents.reduce(
      (acc, agent) => {
        const metrics = getAgentMetrics(agent.id)
        return {
          performance: acc.performance + metrics.performance,
          security: acc.security + metrics.security,
          cost: acc.cost + metrics.cost,
          quality: acc.quality + Number.parseFloat(metrics.quality),
        }
      },
      { performance: 0, security: 0, cost: 0, quality: 0 },
    )

    return {
      performance: `${Math.round(totalMetrics.performance / currentAgents.length)}%`,
      security: `${Math.round(totalMetrics.security / currentAgents.length)}%`,
      cost: `$${Math.round(totalMetrics.cost / currentAgents.length)}`,
      quality: `${(totalMetrics.quality / currentAgents.length).toFixed(1)}/5`,
    }
  }

  const averageMetrics = getAverageMetrics()
  const displayMetrics = selectedAgentData
    ? {
        performance: `${getAgentMetrics(selectedAgentData.id).performance}%`,
        security: `${getAgentMetrics(selectedAgentData.id).security}%`,
        cost: `$${getAgentMetrics(selectedAgentData.id).cost}`,
        quality: `${getAgentMetrics(selectedAgentData.id).quality}/5`,
      }
    : averageMetrics

  // Analytics data based on selected view
  const analyticsData = [
    {
      id: "performance",
      title: "Performance Score",
      value: displayMetrics.performance,
      change: selectedAgentData ? "+1.2%" : "+2.1%",
      trend: "up",
      icon: Zap,
      color: "text-emerald-600 dark:text-emerald-400",
    },
    {
      id: "security",
      title: "Security Rating",
      value: displayMetrics.security,
      change: selectedAgentData ? "+0.1%" : "+0.3%",
      trend: "up",
      icon: Shield,
      color: "text-blue-600 dark:text-blue-400",
    },
    {
      id: "cost",
      title: selectedAgentData ? "Agent Cost" : "Avg Monthly Cost",
      value: displayMetrics.cost,
      change: selectedAgentData ? "-2.1%" : "-5.2%",
      trend: "down",
      icon: DollarSign,
      color: "text-violet-600 dark:text-violet-400",
    },
    {
      id: "conversation",
      title: "Conversation Quality",
      value: displayMetrics.quality,
      change: selectedAgentData ? "+0.1" : "+0.2",
      trend: "up",
      icon: MessageSquare,
      color: "text-orange-600 dark:text-orange-400",
    },
  ]

  const recentActivity = [
    {
      id: 1,
      type: "success",
      title: "Agent Performance Improved",
      description: "Customer Support Bot response time decreased by 15%",
      time: "2 minutes ago",
      icon: TrendingUp,
      color: "text-emerald-600 dark:text-emerald-400",
    },
    {
      id: 2,
      type: "warning",
      title: "High Token Usage Detected",
      description: "Content Generator approaching monthly limit",
      time: "15 minutes ago",
      icon: AlertTriangle,
      color: "text-amber-600 dark:text-amber-400",
    },
    {
      id: 3,
      type: "info",
      title: "New Security Scan Completed",
      description: "All agents passed security compliance check",
      time: "1 hour ago",
      icon: Shield,
      color: "text-blue-600 dark:text-blue-400",
    },
  ]

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
        {analyticsData.map((metric) => {
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
                const agentMetrics = getAgentMetrics(agent.id)
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
            {recentActivity.map((activity) => {
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
            })}
          </CardContent>
        </Card>
      </div>

      {/* Performance Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <PerformanceChart />
        <ResourceUtilization />
      </div>
    </div>
  )
}
