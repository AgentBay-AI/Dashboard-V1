"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { TrendingUp } from "lucide-react"

export function PerformanceChart() {
  const [data, setData] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchPerformanceData = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/performance?timeframe=7d', {
          signal: AbortSignal.timeout(5000)
        })
        if (response.ok) {
          const result = await response.json()
          // Use real data only - no random generation
          const chartData = result.data.map((item: any, index: number) => ({
            day: `Day ${index + 1}`,
            performance: item.success_rate || 0 // Use 0 instead of random
          }))
          setData(chartData.slice(0, 7))
        } else {
          // Show zero data if API fails
          setData(generateZeroData())
        }
      } catch (error) {
        console.error('Failed to fetch performance data:', error)
        // Show zero data on error
        setData(generateZeroData())
      } finally {
        setLoading(false)
      }
    }

    fetchPerformanceData()
  }, [])

  // Generate zero data for 7 days
  const generateZeroData = () => {
    return Array.from({ length: 7 }, (_, index) => ({
      day: `Day ${index + 1}`,
      performance: 0
    }))
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>AI Agent Performance</CardTitle>
        <CardDescription>
          {data.every(d => d.performance === 0) ? (
            "No performance data available"
          ) : (
            "Last 7 Days"
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-[200px] flex items-center justify-center">
            <div className="text-sm text-muted-foreground">Loading performance data...</div>
          </div>
        ) : data.length === 0 || data.every(d => d.performance === 0) ? (
          <div className="h-[200px] flex flex-col items-center justify-center text-center">
            <TrendingUp className="h-8 w-8 text-muted-foreground mb-2" />
            <p className="text-sm text-muted-foreground">No performance data</p>
            <p className="text-xs text-muted-foreground mt-1">Connect agents to see performance metrics</p>
          </div>
        ) : (
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={data}
                margin={{
                  top: 5,
                  right: 10,
                  left: 0,
                  bottom: 5,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                <XAxis dataKey="day" tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 12 }} tickLine={false} axisLine={false} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--background))",
                    borderColor: "hsl(var(--border))",
                    borderRadius: "0.5rem",
                    boxShadow: "0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)",
                  }}
                  itemStyle={{ color: "hsl(var(--foreground))" }}
                  labelStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Line
                  type="monotone"
                  dataKey="performance"
                  stroke="hsl(var(--primary))"
                  strokeWidth={2}
                  dot={{ r: 4, strokeWidth: 2 }}
                  activeDot={{ r: 6, strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
