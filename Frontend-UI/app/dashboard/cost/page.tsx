"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { DollarSign, Calendar, Download, AlertTriangle, Zap, Target, PieChart, BarChart3, Activity } from "lucide-react"
import {
  Bar,
  BarChart,
  Line,
  Pie,
  PieChart as RechartsPieChart,
  Cell,
  Area,
  AreaChart,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
} from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"

export default function CostPage() {
  const [timeRange, setTimeRange] = useState("30d")
  const [selectedProvider, setSelectedProvider] = useState("all")

  // Mock cost data
  const overviewMetrics = [
    {
      title: "Total Cost",
      value: "$2,847.32",
      change: "+12.3%",
      trend: "up",
      icon: DollarSign,
      color: "text-blue-600 dark:text-blue-400",
    },
    {
      title: "Daily Average",
      value: "$94.91",
      change: "-5.2%",
      trend: "down",
      icon: Calendar,
      color: "text-emerald-600 dark:text-emerald-400",
    },
    {
      title: "Cost per Token",
      value: "$0.0023",
      change: "+2.1%",
      trend: "up",
      icon: Target,
      color: "text-violet-600 dark:text-violet-400",
    },
    {
      title: "Budget Status",
      value: "67%",
      change: "On track",
      trend: "neutral",
      icon: Activity,
      color: "text-orange-600 dark:text-orange-400",
    },
  ]

  // Monthly cost trends
  const monthlyData = [
    { month: "Jan", cost: 1850, tokens: 2.1 },
    { month: "Feb", cost: 2100, tokens: 2.4 },
    { month: "Mar", cost: 1950, tokens: 2.2 },
    { month: "Apr", cost: 2300, tokens: 2.6 },
    { month: "May", cost: 2650, tokens: 3.0 },
    { month: "Jun", cost: 2847, tokens: 3.2 },
  ]

  // LLM provider distribution
  const providerData = [
    { name: "OpenAI", cost: 1247, percentage: 43.8, color: "#10b981" },
    { name: "Anthropic", cost: 856, percentage: 30.1, color: "#3b82f6" },
    { name: "Gemini", cost: 423, percentage: 14.9, color: "#f59e0b" },
    { name: "Groq", cost: 321, percentage: 11.3, color: "#ef4444" },
  ]

  // Daily cost data
  const dailyData = [
    { date: "Jun 1", openai: 45, anthropic: 32, gemini: 18, groq: 12 },
    { date: "Jun 2", openai: 52, anthropic: 28, gemini: 22, groq: 15 },
    { date: "Jun 3", openai: 38, anthropic: 35, gemini: 16, groq: 18 },
    { date: "Jun 4", openai: 61, anthropic: 42, gemini: 25, groq: 14 },
    { date: "Jun 5", openai: 48, anthropic: 38, gemini: 20, groq: 16 },
    { date: "Jun 6", openai: 55, anthropic: 31, gemini: 24, groq: 19 },
    { date: "Jun 7", openai: 43, anthropic: 29, gemini: 17, groq: 13 },
  ]

  // Feature usage breakdown
  const featureData = [
    { feature: "Chat Completions", cost: 1456, percentage: 51.2, requests: 45200 },
    { feature: "Embeddings", cost: 623, percentage: 21.9, requests: 18900 },
    { feature: "Image Generation", cost: 445, percentage: 15.6, requests: 3400 },
    { feature: "Audio Processing", cost: 323, percentage: 11.3, requests: 2100 },
  ]

  // Cost projections
  const projectionData = [
    { month: "Jul", actual: null, projected: 3100, optimized: 2650 },
    { month: "Aug", actual: null, projected: 3350, optimized: 2800 },
    { month: "Sep", actual: null, projected: 3600, optimized: 2950 },
    { month: "Oct", actual: null, projected: 3850, optimized: 3100 },
    { month: "Nov", actual: null, projected: 4100, optimized: 3250 },
    { month: "Dec", actual: null, projected: 4350, optimized: 3400 },
  ]

  // Optimization recommendations
  const recommendations = [
    {
      title: "Switch to GPT-4o Mini for Simple Tasks",
      description: "Use GPT-4o Mini for basic queries to reduce costs by up to 60%",
      savings: "$450/month",
      impact: "high",
    },
    {
      title: "Implement Response Caching",
      description: "Cache common responses to reduce redundant API calls",
      savings: "$280/month",
      impact: "medium",
    },
    {
      title: "Optimize Token Usage",
      description: "Reduce prompt length and implement better context management",
      savings: "$180/month",
      impact: "medium",
    },
    {
      title: "Use Batch Processing",
      description: "Process multiple requests in batches for better pricing",
      savings: "$120/month",
      impact: "low",
    },
  ]

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cost Tracking</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Monitor and optimize your AI agent costs across all providers
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
              <SelectItem value="1y">Last year</SelectItem>
            </SelectContent>
          </Select>

          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {overviewMetrics.map((metric) => {
          const Icon = metric.icon
          return (
            <Card key={metric.title}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-muted-foreground mb-1">{metric.title}</p>
                    <p className="text-xl font-semibold">{metric.value}</p>
                    <p
                      className={`text-sm font-medium mt-1 ${
                        metric.trend === "up"
                          ? "text-red-600 dark:text-red-400"
                          : metric.trend === "down"
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-muted-foreground"
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

      {/* Detailed Cost Analysis */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="providers">By Provider</TabsTrigger>
          <TabsTrigger value="features">By Feature</TabsTrigger>
          <TabsTrigger value="projections">Projections</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Monthly Trends */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <BarChart3 className="h-5 w-5 mr-2" />
                  Monthly Cost Trends
                </CardTitle>
                <CardDescription>Cost and token usage over time</CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer
                  config={{
                    cost: {
                      label: "Cost ($)",
                      color: "hsl(var(--chart-1))",
                    },
                  }}
                  className="h-[250px]"
                >
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={monthlyData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="month" />
                      <YAxis />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="cost" fill="var(--color-cost)" name="Cost ($)" />
                    </BarChart>
                  </ResponsiveContainer>
                </ChartContainer>
              </CardContent>
            </Card>

            {/* LLM Distribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <PieChart className="h-5 w-5 mr-2" />
                  LLM Provider Distribution
                </CardTitle>
                <CardDescription>Cost breakdown by provider</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[250px] flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <RechartsPieChart>
                      <Pie
                        data={providerData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="cost"
                      >
                        {providerData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip formatter={(value) => [`$${value}`, "Cost"]} />
                      <Legend />
                    </RechartsPieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* By Provider Tab */}
        <TabsContent value="providers" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Daily Costs by Provider */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Daily Costs by Provider</CardTitle>
                <CardDescription>Last 7 days cost breakdown</CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer
                  config={{
                    openai: {
                      label: "OpenAI",
                      color: "#10b981",
                    },
                    anthropic: {
                      label: "Anthropic",
                      color: "#3b82f6",
                    },
                    gemini: {
                      label: "Gemini",
                      color: "#f59e0b",
                    },
                    groq: {
                      label: "Groq",
                      color: "#ef4444",
                    },
                  }}
                  className="h-[250px]"
                >
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={dailyData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" />
                      <YAxis />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Legend />
                      <Line type="monotone" dataKey="openai" stroke="#10b981" strokeWidth={2} />
                      <Line type="monotone" dataKey="anthropic" stroke="#3b82f6" strokeWidth={2} />
                      <Line type="monotone" dataKey="gemini" stroke="#f59e0b" strokeWidth={2} />
                      <Line type="monotone" dataKey="groq" stroke="#ef4444" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </ChartContainer>
              </CardContent>
            </Card>

            {/* Provider Details */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Provider Details</CardTitle>
                <CardDescription>Detailed breakdown by provider</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {providerData.map((provider) => (
                  <div key={provider.name} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: provider.color }} />
                      <div>
                        <p className="font-medium text-sm">{provider.name}</p>
                        <p className="text-xs text-muted-foreground">{provider.percentage}% of total</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-sm">${provider.cost}</p>
                      <Badge variant="outline" className="text-xs">
                        Active
                      </Badge>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* By Feature Tab */}
        <TabsContent value="features" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Feature Cost Breakdown */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Feature Usage Costs</CardTitle>
                <CardDescription>Cost breakdown by feature type</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {featureData.map((feature) => (
                  <div key={feature.feature} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{feature.feature}</span>
                      <span className="font-semibold text-sm">${feature.cost}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>{feature.requests.toLocaleString()} requests</span>
                      <span>{feature.percentage}%</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${feature.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Cost per Request */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Cost Efficiency</CardTitle>
                <CardDescription>Cost per request by feature</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {featureData.map((feature) => {
                  const costPerRequest = (feature.cost / feature.requests).toFixed(4)
                  return (
                    <div key={feature.feature} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                      <div>
                        <p className="font-medium text-sm">{feature.feature}</p>
                        <p className="text-xs text-muted-foreground">{feature.requests.toLocaleString()} requests</p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold text-sm">${costPerRequest}</p>
                        <p className="text-xs text-muted-foreground">per request</p>
                      </div>
                    </div>
                  )
                })}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Projections Tab */}
        <TabsContent value="projections" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Cost Projections */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <BarChart3 className="h-5 w-5 mr-2" />
                  Cost Projections
                </CardTitle>
                <CardDescription>Projected vs optimized costs</CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer
                  config={{
                    projected: {
                      label: "Projected",
                      color: "hsl(var(--chart-1))",
                    },
                    optimized: {
                      label: "Optimized",
                      color: "hsl(var(--chart-2))",
                    },
                  }}
                  className="h-[250px]"
                >
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={projectionData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="month" />
                      <YAxis />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Legend />
                      <Area
                        type="monotone"
                        dataKey="projected"
                        stackId="1"
                        stroke="var(--color-projected)"
                        fill="var(--color-projected)"
                        fillOpacity={0.6}
                      />
                      <Area
                        type="monotone"
                        dataKey="optimized"
                        stackId="2"
                        stroke="var(--color-optimized)"
                        fill="var(--color-optimized)"
                        fillOpacity={0.6}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </ChartContainer>
              </CardContent>
            </Card>

            {/* Optimization Recommendations */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <Zap className="h-5 w-5 mr-2" />
                  Optimization Recommendations
                </CardTitle>
                <CardDescription>Ways to reduce your costs</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {recommendations.map((rec, index) => (
                  <div key={index} className="p-3 border rounded-lg">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-medium text-sm">{rec.title}</h4>
                      <Badge
                        variant={rec.impact === "high" ? "default" : rec.impact === "medium" ? "secondary" : "outline"}
                        className="text-xs"
                      >
                        {rec.impact} impact
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-3">{rec.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-emerald-600 dark:text-emerald-400">
                        Save {rec.savings}
                      </span>
                      <Button size="sm" variant="outline">
                        Apply
                      </Button>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Budget Alert */}
          <Card className="border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/20">
            <CardContent className="p-4">
              <div className="flex items-start space-x-3">
                <div className="p-2 bg-amber-100 dark:bg-amber-900/30 rounded-lg">
                  <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                </div>
                <div className="flex-1">
                  <h3 className="font-medium text-amber-900 dark:text-amber-100 mb-1">Budget Alert</h3>
                  <p className="text-sm text-amber-800 dark:text-amber-200 mb-3">
                    You're currently at 67% of your monthly budget ($4,250). At the current rate, you'll exceed your
                    budget by approximately $380 this month.
                  </p>
                  <div className="flex items-center space-x-3">
                    <Button size="sm" className="bg-amber-600 hover:bg-amber-700 text-white">
                      Adjust Budget
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-amber-300 text-amber-700 dark:text-amber-300 bg-transparent"
                    >
                      View Recommendations
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
