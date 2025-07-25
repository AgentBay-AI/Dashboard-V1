"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts"
import {
  TrendingUp,
  TrendingDown,
  Eye,
  Users,
  Clock,
  MousePointer,
  Smartphone,
  Activity,
  AlertCircle,
  Download,
  Calendar,
  Filter,
  RefreshCw,
  Monitor,
  Globe,
  CheckCircle,
} from "lucide-react"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"

export default function FrontendAnalyticsPage() {
  const [timeRange, setTimeRange] = useState("7d")
  const [selectedMetric, setSelectedMetric] = useState("all")
  
  // Type for overview metrics
  interface OverviewMetric {
    title: string
    value: string
    change: string
    trend: string
    icon: any
    color: string
  }

  // Type for device data
  interface DeviceData {
    name: string
    value: number
    color: string
  }

  // Type for top pages
  interface TopPage {
    page: string
    views: number
    uniqueViews: number
    avgTime: string
  }

  // Type for geo data
  interface GeoData {
    country: string
    visitors: number
    percentage: number
  }
  
  const [overviewMetrics, setOverviewMetrics] = useState<OverviewMetric[]>([])
  const [loading, setLoading] = useState(true)

  // Fetch real frontend analytics data
  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        setLoading(true)
        const response = await fetch(`http://localhost:8080/api/analytics/frontend-stats?timeframe=${timeRange}`)
        if (response.ok) {
          const result = await response.json()
          setOverviewMetrics(result.data.metrics || [])
        } else {
          // Show empty state if no data available
          setOverviewMetrics([
            {
              title: "Total Page Views",
              value: "0",
              change: "0%",
              trend: "up",
              icon: Eye,
              color: "text-blue-600 dark:text-blue-400",
            },
            {
              title: "Unique Visitors", 
              value: "0",
              change: "0%",
              trend: "up",
              icon: Users,
              color: "text-emerald-600 dark:text-emerald-400",
            },
            {
              title: "Avg Session Duration",
              value: "0s",
              change: "0%",
              trend: "up",
              icon: Clock,
              color: "text-violet-600 dark:text-violet-400",
            },
            {
              title: "Bounce Rate",
              value: "0%",
              change: "0%",
              trend: "down",
              icon: MousePointer,
              color: "text-orange-600 dark:text-orange-400",
            },
            {
              title: "Mobile Traffic",
              value: "0%",
              change: "0%",
              trend: "up",
              icon: Smartphone,
              color: "text-pink-600 dark:text-pink-400",
            },
            {
              title: "Page Load Speed",
              value: "0s",
              change: "0s",
              trend: "down",
              icon: Activity,
              color: "text-cyan-600 dark:text-cyan-400",
            },
            {
              title: "Conversion Rate",
              value: "0%",
              change: "0%",
              trend: "up",
              icon: TrendingUp,
              color: "text-green-600 dark:text-green-400",
            },
            {
              title: "Error Rate",
              value: "0%",
              change: "0%",
              trend: "down",
              icon: AlertCircle,
              color: "text-red-600 dark:text-red-400",
            },
          ])
        }
      } catch (error) {
        console.error('Failed to fetch frontend analytics:', error)
        // Show empty state on error
        setOverviewMetrics([])
      } finally {
        setLoading(false)
      }
    }

    fetchAnalytics()
  }, [timeRange])

  // All chart data from backend - empty until real data loads
  const [trafficData, setTrafficData] = useState<any[]>([])
  const [deviceData, setDeviceData] = useState<DeviceData[]>([])
  const [topPages, setTopPages] = useState<TopPage[]>([])
  const [geoData, setGeoData] = useState<GeoData[]>([])
  const [userFlowData, setUserFlowData] = useState<any[]>([])
  const [conversionData, setConversionData] = useState<any[]>([])

  // Fetch all chart data from backend
  useEffect(() => {
    const fetchChartData = async () => {
      try {
        // All frontend analytics chart data would come from backend
        // Currently showing empty state since no analytics data exists
        setTrafficData([])
        setDeviceData([])
        setTopPages([])
        setGeoData([])
        setUserFlowData([])
        setConversionData([])
      } catch (error) {
        console.error('Failed to fetch frontend chart data:', error)
        // Keep empty states
      }
    }

    if (!loading) {
      fetchChartData()
    }
  }, [timeRange, loading])

  // All error and real-time data from backend - empty until real data loads
  const [errorData, setErrorData] = useState<any[]>([])
  const [realTimeData, setRealTimeData] = useState({
    activeUsers: 0,
    currentPageViews: 0,
    topActivePages: [] as any[],
  })

  // Fetch error and real-time data from backend
  useEffect(() => {
    const fetchErrorData = async () => {
      try {
        // Error data would come from backend error tracking API
        // Currently showing empty state since no error data exists
        setErrorData([])
        setRealTimeData({
          activeUsers: 0,
          currentPageViews: 0,
          topActivePages: [],
        })
      } catch (error) {
        console.error('Failed to fetch error data:', error)
        // Keep empty states
      }
    }

    if (!loading) {
      fetchErrorData()
    }
  }, [loading])

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Frontend Analytics</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Comprehensive insights into your application's frontend performance and user behavior
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
            </SelectContent>
          </Select>

          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>

          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {loading ? (
          <p>Loading analytics...</p>
        ) : overviewMetrics.length === 0 ? (
          <p>No analytics data available for the selected timeframe.</p>
        ) : (
          overviewMetrics.map((metric) => {
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

      {/* Detailed Analytics */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="audience">Audience</TabsTrigger>
          <TabsTrigger value="behavior">Behavior</TabsTrigger>
          <TabsTrigger value="errors">Errors</TabsTrigger>
          <TabsTrigger value="realtime">Real-time</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Traffic Trends */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <TrendingUp className="h-5 w-5 mr-2" />
                  Traffic Trends
                </CardTitle>
                <CardDescription>Page views and unique visitors over time</CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer
                  config={{
                    pageViews: {
                      label: "Page Views",
                      color: "hsl(var(--chart-1))",
                    },
                    uniqueVisitors: {
                      label: "Unique Visitors",
                      color: "hsl(var(--chart-2))",
                    },
                  }}
                  className="h-[250px]"
                >
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trafficData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" />
                      <YAxis />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Area
                        type="monotone"
                        dataKey="pageViews"
                        stackId="1"
                        stroke="hsl(var(--chart-1))"
                        fill="hsl(var(--chart-1))"
                        fillOpacity={0.6}
                      />
                      <Area
                        type="monotone"
                        dataKey="uniqueVisitors"
                        stackId="2"
                        stroke="hsl(var(--chart-2))"
                        fill="hsl(var(--chart-2))"
                        fillOpacity={0.6}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </ChartContainer>
              </CardContent>
            </Card>

            {/* Device Breakdown */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <Monitor className="h-5 w-5 mr-2" />
                  Device Breakdown
                </CardTitle>
                <CardDescription>Traffic distribution by device type</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[250px] flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={deviceData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {deviceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip formatter={(value) => [`${value}%`, "Traffic"]} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Performance Tab */}
        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top Pages */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Top Pages</CardTitle>
                <CardDescription>Most visited pages and their performance</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {topPages.map((page, index) => (
                  <div key={page.page} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <p className="font-medium text-sm">{page.page}</p>
                      <div className="flex items-center space-x-4 text-xs text-muted-foreground mt-1">
                        <span>{page.views.toLocaleString()} views</span>
                        <span>{page.uniqueViews.toLocaleString()} unique</span>
                        <span>{page.avgTime} avg time</span>
                      </div>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      #{index + 1}
                    </Badge>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Geographic Distribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <Globe className="h-5 w-5 mr-2" />
                  Geographic Distribution
                </CardTitle>
                <CardDescription>Visitors by country</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {geoData.map((country) => (
                  <div key={country.country} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{country.country}</span>
                      <span className="text-sm">{country.visitors.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <div className="w-full bg-muted rounded-full h-2 mr-2">
                        <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${country.percentage}%` }} />
                      </div>
                      <span>{country.percentage}%</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Audience Tab */}
        <TabsContent value="audience" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Audience Insights</CardTitle>
                <CardDescription>User demographics and behavior patterns</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <p className="text-2xl font-semibold">67%</p>
                    <p className="text-sm text-muted-foreground">Returning Visitors</p>
                  </div>
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <p className="text-2xl font-semibold">33%</p>
                    <p className="text-sm text-muted-foreground">New Visitors</p>
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Age 25-34</span>
                    <span>42%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Age 35-44</span>
                    <span>28%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Age 45-54</span>
                    <span>18%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Other</span>
                    <span>12%</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Session Duration</CardTitle>
                <CardDescription>Average time spent on the platform</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="text-center">
                    <p className="text-3xl font-semibold">4m 32s</p>
                    <p className="text-sm text-muted-foreground">Average Session Duration</p>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>0-1 min</span>
                      <span>15%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>1-3 min</span>
                      <span>25%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>3-5 min</span>
                      <span>35%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>5+ min</span>
                      <span>25%</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Behavior Tab */}
        <TabsContent value="behavior" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg font-medium">User Flow</CardTitle>
              <CardDescription>How users navigate through your application</CardDescription>
            </CardHeader>
            <CardContent>
              <ChartContainer
                config={{
                  users: {
                    label: "Users",
                    color: "hsl(var(--chart-1))",
                  },
                }}
                className="h-[300px]"
              >
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={userFlowData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="step" />
                    <YAxis />
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Bar dataKey="users" fill="hsl(var(--chart-1))" />
                  </BarChart>
                </ResponsiveContainer>
              </ChartContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Errors Tab */}
        <TabsContent value="errors" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <AlertCircle className="h-5 w-5 mr-2" />
                  Error Breakdown
                </CardTitle>
                <CardDescription>Most common errors and their frequency</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {errorData.map((error) => (
                  <div key={error.type} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{error.type}</span>
                      <span className="text-sm">{error.count}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <div className="w-full bg-muted rounded-full h-2 mr-2">
                        <div className="bg-red-500 h-2 rounded-full" style={{ width: `${error.percentage}%` }} />
                      </div>
                      <span>{error.percentage}%</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Error Status</CardTitle>
                <CardDescription>Current system health overview</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-emerald-50 dark:bg-emerald-950/20 rounded-lg">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="h-4 w-4 text-emerald-600" />
                    <span className="font-medium text-sm">System Status</span>
                  </div>
                  <Badge variant="secondary" className="bg-emerald-100 text-emerald-700 border-emerald-200">
                    Operational
                  </Badge>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Uptime (24h)</span>
                    <span className="text-emerald-600">99.8%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Response Time</span>
                    <span>1.2s avg</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Error Rate</span>
                    <span className="text-red-600">0.12%</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Real-time Tab */}
        <TabsContent value="realtime" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <Activity className="h-5 w-5 mr-2" />
                  Real-time Activity
                </CardTitle>
                <CardDescription>Current active users and page views</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-center">
                  <p className="text-4xl font-semibold text-emerald-600">{realTimeData.activeUsers}</p>
                  <p className="text-sm text-muted-foreground">Active Users Right Now</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-semibold">{realTimeData.currentPageViews}</p>
                  <p className="text-sm text-muted-foreground">Page Views in Last Minute</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium">Active Pages</CardTitle>
                <CardDescription>Most active pages right now</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {realTimeData.topActivePages.map((page, index) => (
                  <div key={page.page} className="flex items-center justify-between p-2 border rounded-lg">
                    <span className="font-medium text-sm">{page.page}</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">{page.activeUsers}</span>
                      <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
