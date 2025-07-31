"use client"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import {
  ArrowRight,
  Play,
  Zap,
  Shield,
  DollarSign,
  MessageSquare,
  Activity,
  Bot,
  TrendingUp,
  Info,
  Loader2,
} from "lucide-react"
import Link from "next/link"
import { useState, useEffect } from "react"

export function LandingHero() {
  const [currentFeature, setCurrentFeature] = useState(0)
  const [selectedMetric, setSelectedMetric] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [dashboardData, setDashboardData] = useState({
    activeAgents: 12,
    alerts: 3,
    performance: 94,
    security: 98,
    cost: 2847,
    requests: 15420,
  })

  // Dummy agent data - set to empty array to test empty state
  const [agents, setAgents] = useState([
    {
      id: 1,
      name: "Customer Support Bot",
      status: "Online" as const,
      uptime: 99.8,
      tokenUsage: 45230,
      cost: 234.5,
      provider: "OpenAI",
      lastActive: "2 min ago",
    },
    {
      id: 2,
      name: "Content Generator",
      status: "Online" as const,
      uptime: 97.2,
      tokenUsage: 78940,
      cost: 412.3,
      provider: "Anthropic",
      lastActive: "5 min ago",
    },
    {
      id: 3,
      name: "Data Analyzer",
      status: "Offline" as const,
      uptime: 89.5,
      tokenUsage: 23100,
      cost: 156.8,
      provider: "Google",
      lastActive: "2 hours ago",
    },
    {
      id: 4,
      name: "Translation Service",
      status: "Online" as const,
      uptime: 95.7,
      tokenUsage: 34560,
      cost: 189.2,
      provider: "OpenAI",
      lastActive: "1 min ago",
    },
    {
      id: 5,
      name: "Code Assistant",
      status: "Online" as const,
      uptime: 92.3,
      tokenUsage: 56780,
      cost: 298.7,
      provider: "Anthropic",
      lastActive: "3 min ago",
    },
    {
      id: 6,
      name: "Email Classifier",
      status: "Offline" as const,
      uptime: 88.1,
      tokenUsage: 12340,
      cost: 87.4,
      provider: "Google",
      lastActive: "4 hours ago",
    },
  ])

  const [activeTab, setActiveTab] = useState("dashboard")

  const features = [
    "Real-time AI agent monitoring across all platforms",
    "Advanced security compliance and threat detection",
    "Cost optimization with detailed usage analytics",
    "Performance insights and automated scaling",
  ]

  const tabs = [
    { id: "dashboard", label: "Dashboard", icon: Activity },
    { id: "logs", label: "Agent Logs", icon: Bot },
    { id: "insights", label: "Cost Insights", icon: DollarSign },
  ]

  // Simulate initial loading
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false)
    }, 1500)
    return () => clearTimeout(timer)
  }, [])

  // Auto-rotate features
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentFeature((prev) => (prev + 1) % features.length)
    }, 3000)
    return () => clearInterval(interval)
  }, [features.length])

  // Simulate live data updates
  useEffect(() => {
    if (!isLoading) {
      const interval = setInterval(() => {
        setDashboardData((prev) => ({
          activeAgents: prev.activeAgents + Math.floor(Math.random() * 3) - 1,
          alerts: Math.max(0, prev.alerts + Math.floor(Math.random() * 3) - 1),
          performance: Math.min(100, Math.max(85, prev.performance + Math.floor(Math.random() * 6) - 3)),
          security: Math.min(100, Math.max(90, prev.security + Math.floor(Math.random() * 4) - 2)),
          cost: prev.cost + Math.floor(Math.random() * 100) - 50,
          requests: prev.requests + Math.floor(Math.random() * 500) + 100,
        }))
      }, 3000)
      return () => clearInterval(interval)
    }
  }, [isLoading])

  // Auto-highlight metrics
  useEffect(() => {
    if (!isLoading) {
      const metrics = ["performance", "security", "cost", "requests"]
      const interval = setInterval(() => {
        const randomMetric = metrics[Math.floor(Math.random() * metrics.length)]
        setSelectedMetric(randomMetric)
        setTimeout(() => setSelectedMetric(null), 1500)
      }, 2000)
      return () => clearInterval(interval)
    }
  }, [isLoading])

  const onlineAgents = agents.filter((agent) => agent.status === "Online")
  const offlineAgents = agents.filter((agent) => agent.status === "Offline")

  const renderLoadingState = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading demo data...</span>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="p-4 rounded-lg border">
            <Skeleton className="h-4 w-20 mb-2" />
            <Skeleton className="h-8 w-16" />
          </div>
        ))}
      </div>
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="p-4 border rounded-lg">
            <div className="flex items-center gap-3">
              <Skeleton className="h-3 w-3 rounded-full" />
              <div className="flex-1">
                <Skeleton className="h-4 w-32 mb-1" />
                <Skeleton className="h-3 w-24" />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const renderDashboardContent = () => {
    if (isLoading) {
      return renderLoadingState()
    }

    switch (activeTab) {
      case "dashboard":
        return (
          <div className="space-y-8">
            {/* Sample Data Message */}
            <Alert className="border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20">
              <Info className="h-4 w-4 text-blue-600" />
              <AlertDescription className="text-blue-800 dark:text-blue-200">
                Showing sample agent data. Connect your backend to enable real-time monitoring.
              </AlertDescription>
            </Alert>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
              <div
                className={`p-5 rounded-lg border transition-all cursor-pointer ${
                  selectedMetric === "performance"
                    ? "border-blue-300 bg-blue-50 dark:border-blue-600 dark:bg-blue-950/20"
                    : "border-border hover:border-border/60"
                }`}
                onClick={() => setSelectedMetric("performance")}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Performance</p>
                    <p className="text-2xl font-bold">{dashboardData.performance}%</p>
                  </div>
                  <Zap className="h-5 w-5 text-emerald-600" />
                </div>
              </div>

              <div
                className={`p-5 rounded-lg border transition-all cursor-pointer ${
                  selectedMetric === "security"
                    ? "border-blue-300 bg-blue-50 dark:border-blue-600 dark:bg-blue-950/20"
                    : "border-border hover:border-border/60"
                }`}
                onClick={() => setSelectedMetric("security")}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Security</p>
                    <p className="text-2xl font-bold">{dashboardData.security}%</p>
                  </div>
                  <Shield className="h-5 w-5 text-blue-600" />
                </div>
              </div>

              <div
                className={`p-5 rounded-lg border transition-all cursor-pointer ${
                  selectedMetric === "cost"
                    ? "border-blue-300 bg-blue-50 dark:border-blue-600 dark:bg-blue-950/20"
                    : "border-border hover:border-border/60"
                }`}
                onClick={() => setSelectedMetric("cost")}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Monthly Cost</p>
                    <p className="text-2xl font-bold">${dashboardData.cost.toLocaleString()}</p>
                  </div>
                  <DollarSign className="h-5 w-5 text-violet-600" />
                </div>
              </div>

              <div
                className={`p-5 rounded-lg border transition-all cursor-pointer ${
                  selectedMetric === "requests"
                    ? "border-blue-300 bg-blue-50 dark:border-blue-600 dark:bg-blue-950/20"
                    : "border-border hover:border-border/60"
                }`}
                onClick={() => setSelectedMetric("requests")}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Requests</p>
                    <p className="text-2xl font-bold">{dashboardData.requests.toLocaleString()}</p>
                  </div>
                  <MessageSquare className="h-5 w-5 text-orange-600" />
                </div>
              </div>
            </div>

            {/* Agent List */}
            <div>
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold">Connected Agents</h3>
                {agents.length > 0 && (
                  <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <div className="h-2 w-2 bg-emerald-500 rounded-full"></div>
                      <span>{onlineAgents.length} Online</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <div className="h-2 w-2 bg-red-500 rounded-full"></div>
                      <span>{offlineAgents.length} Offline</span>
                    </div>
                  </div>
                )}
              </div>

              {agents.length > 0 ? (
                <div className="grid gap-5">
                  {agents.map((agent) => (
                    <div
                      key={agent.id}
                      className="flex flex-col sm:flex-row sm:items-center justify-between p-5 border rounded-lg hover:shadow-sm transition-all"
                    >
                      <div className="flex items-center gap-3 mb-3 sm:mb-0">
                        <div className="relative">
                          <div
                            className={`h-3 w-3 rounded-full ${
                              agent.status === "Online" ? "bg-emerald-500" : "bg-red-500"
                            }`}
                          />
                          {agent.status === "Online" && (
                            <div className="absolute inset-0 h-3 w-3 rounded-full bg-emerald-500 animate-ping opacity-75" />
                          )}
                        </div>
                        <div>
                          <h4 className="font-semibold text-base">{agent.name}</h4>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <span className={agent.status === "Online" ? "text-emerald-600" : "text-red-600"}>
                              {agent.status}
                            </span>
                            <span>•</span>
                            <span>{agent.provider}</span>
                            <span>•</span>
                            <span>{agent.lastActive}</span>
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-6 text-sm">
                        <div className="text-center">
                          <p className="font-semibold">{agent.uptime}%</p>
                          <p className="text-muted-foreground">Uptime</p>
                        </div>
                        <div className="text-center">
                          <p className="font-semibold">{agent.tokenUsage.toLocaleString()}</p>
                          <p className="text-muted-foreground">Tokens</p>
                        </div>
                        <div className="text-center">
                          <p className="font-semibold">${agent.cost}</p>
                          <p className="text-muted-foreground">Cost</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 border rounded-lg bg-muted/20">
                  <Bot className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <h3 className="text-lg font-semibold mb-2">No agents found</h3>
                  <p className="text-muted-foreground mb-4">Connect your backend to begin monitoring.</p>
                  <Button variant="outline" disabled>
                    Connect Backend
                  </Button>
                </div>
              )}
            </div>
          </div>
        )

      case "logs":
        return (
          <div className="space-y-6">
            <Alert className="border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20">
              <Info className="h-4 w-4 text-blue-600" />
              <AlertDescription className="text-blue-800 dark:text-blue-200">
                Agent logs will appear here once you connect your backend.
              </AlertDescription>
            </Alert>
            <div className="text-center py-12">
              <Bot className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">Agent Logs</h3>
              <p className="text-muted-foreground">View detailed logs and activity history for all your agents</p>
            </div>
          </div>
        )

      case "insights":
        return (
          <div className="space-y-6">
            <Alert className="border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20">
              <Info className="h-4 w-4 text-blue-600" />
              <AlertDescription className="text-blue-800 dark:text-blue-200">
                Cost insights and analytics will be available after backend integration.
              </AlertDescription>
            </Alert>
            <div className="text-center py-12">
              <TrendingUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">Cost Insights</h3>
              <p className="text-muted-foreground">Analyze spending patterns and optimize your AI agent costs</p>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <section className="relative overflow-hidden bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-950 dark:via-blue-950 dark:to-indigo-950">
      <div className="absolute inset-0 bg-grid-slate-100 [mask-image:linear-gradient(0deg,white,rgba(255,255,255,0.6))] dark:bg-grid-slate-700/25" />

      <div className="relative mx-auto max-w-7xl px-6 py-12 sm:py-16 lg:px-8 lg:py-20 xl:py-24">
        <div className="grid lg:grid-cols-2 gap-12 items-start lg:items-center">
          {/* Left Column - Content */}
          <div className="text-center lg:text-left pt-8 lg:pt-0">
            <div className="mb-12 lg:mb-16">
              <Badge
                variant="secondary"
                className="mb-6 bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 text-base px-4 py-2"
              >
                🚀 Now in Beta
              </Badge>
              <h1 className="text-5xl font-bold tracking-tight text-slate-900 dark:text-slate-100 sm:text-6xl lg:text-6xl xl:text-7xl leading-tight">
                The{" "}
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent">
                  HR Department
                </span>{" "}
                for Your AI Agents
              </h1>
            </div>

            <div className="mb-8 h-16">
              <p className="text-xl text-slate-600 dark:text-slate-400 transition-all duration-500">
                {features[currentFeature]}
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start mb-8">
              <Button size="lg" className="bg-blue-600 hover:bg-blue-700" asChild>
                <Link href="/dashboard">
                  Start Monitoring
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button size="lg" variant="outline" className="group bg-transparent">
                <Play className="mr-2 h-4 w-4 group-hover:scale-110 transition-transform" />
                Watch Demo
              </Button>
            </div>

            <div className="flex items-center justify-center lg:justify-start gap-8 text-sm text-slate-600 dark:text-slate-400">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 bg-emerald-500 rounded-full animate-pulse" />
                <span>Live Monitoring</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 bg-blue-500 rounded-full animate-pulse" />
                <span>Real-time Alerts</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 bg-purple-500 rounded-full animate-pulse" />
                <span>Cost Optimization</span>
              </div>
            </div>
          </div>

          {/* Right Column - Interactive Dashboard */}
          <div className="relative">
            <Card className="w-full max-w-2xl mx-auto shadow-2xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-sm">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-xl font-semibold">Nexus AI Dashboard</CardTitle>
                    <CardDescription>Live monitoring and analytics</CardDescription>
                  </div>
                  <div className="flex items-center gap-1">
                    <div className="h-2 w-2 bg-emerald-500 rounded-full animate-pulse" />
                    <span className="text-xs text-muted-foreground">Live</span>
                  </div>
                </div>

                {/* Tab Navigation */}
                <div className="flex gap-1 mt-4 p-1 bg-muted rounded-lg">
                  {tabs.map((tab) => {
                    const Icon = tab.icon
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                          activeTab === tab.id
                            ? "bg-background text-foreground shadow-sm"
                            : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        <Icon className="h-4 w-4" />
                        <span className="hidden sm:inline">{tab.label}</span>
                      </button>
                    )
                  })}
                </div>
              </CardHeader>

              <CardContent className="space-y-6">{renderDashboardContent()}</CardContent>
            </Card>

            {/* Floating Elements */}
            <div className="absolute -top-4 -right-4 w-24 h-24 bg-gradient-to-br from-blue-400 to-purple-600 rounded-full opacity-20 animate-pulse" />
            <div className="absolute -bottom-8 -left-8 w-32 h-32 bg-gradient-to-br from-indigo-400 to-cyan-600 rounded-full opacity-10 animate-pulse" />
          </div>
        </div>
      </div>
    </section>
  )
}
