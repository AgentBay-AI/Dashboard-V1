"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { AlertTriangle } from "lucide-react"

export function FailedSessionsChart() {
  const [data, setData] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchFailureData = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/failed-sessions', {
          signal: AbortSignal.timeout(5000)
        })
        if (response.ok) {
          const result = await response.json()
          setData(result.data || [])
        } else {
          setData(generateZeroData())
        }
      } catch (error) {
        console.error('Failed to fetch failure data:', error)
        setData(generateZeroData())
      } finally {
        setLoading(false)
      }
    }

    fetchFailureData()
  }, [])

  const generateZeroData = () => {
    const dates = []
    for (let i = 6; i >= 0; i--) {
      const date = new Date()
      date.setDate(date.getDate() - i)
      dates.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        failures: 0
      })
    }
    return dates
  }

  const hasFailures = data.some(d => d.failures > 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Failed Sessions</CardTitle>
        <CardDescription>Number of failures over time</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-[200px] flex items-center justify-center">
            <div className="text-sm text-muted-foreground">Loading failure data...</div>
          </div>
        ) : !hasFailures ? (
          <div className="h-[200px] flex flex-col items-center justify-center text-center">
            <AlertTriangle className="h-8 w-8 text-emerald-500 mb-2" />
            <p className="text-sm text-emerald-600 font-medium">No failures detected</p>
            <p className="text-xs text-muted-foreground mt-1">All sessions completed successfully</p>
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
                <XAxis dataKey="date" tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
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
                  dataKey="failures"
                  stroke="#e11d48"
                  strokeWidth={2}
                  dot={{ r: 3, strokeWidth: 2 }}
                  activeDot={{ r: 5, strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
