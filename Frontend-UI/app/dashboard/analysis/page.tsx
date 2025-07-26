"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { RiskAssessment } from "@/components/dashboard/risk-assessment"
import { SessionHistoryChart } from "@/components/dashboard/session-history-chart"
import { FailedSessionsChart } from "@/components/dashboard/failed-sessions-chart"
import { PieChart } from "lucide-react"

export default function AnalysisPage() {
  const [sessionData, setSessionData] = useState({
    total: 0,
    successful: 0,
    failed: 0,
    pending: 0
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchSessionData = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/session-stats', {
          signal: AbortSignal.timeout(5000)
        })
        if (response.ok) {
          const result = await response.json()
          setSessionData(result.data || {
            total: 0,
            successful: 0,
            failed: 0,
            pending: 0
          })
        }
      } catch (error) {
        console.error('Failed to fetch session data:', error)
        // Keep zero state
      } finally {
        setLoading(false)
      }
    }

    fetchSessionData()
  }, [])

  const successPercentage = sessionData.total > 0 ? (sessionData.successful / sessionData.total) * 100 : 0
  const failedPercentage = sessionData.total > 0 ? (sessionData.failed / sessionData.total) * 100 : 0

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Analysis</h1>
        <p className="text-muted-foreground">Detailed analysis of your AI agent's performance and behavior.</p>
      </div>

      <RiskAssessment />

      <div className="grid gap-4 md:grid-cols-2">
        <SessionHistoryChart />
        <Card>
          <CardHeader>
            <CardTitle>Session End States</CardTitle>
            <CardDescription>Distribution of session outcomes</CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            {loading ? (
              <div className="h-60 w-60 flex items-center justify-center">
                <div className="text-sm text-muted-foreground">Loading...</div>
              </div>
            ) : sessionData.total === 0 ? (
              <div className="h-60 w-60 flex flex-col items-center justify-center text-center">
                <PieChart className="h-12 w-12 text-muted-foreground mb-3" />
                <div className="text-lg font-semibold text-muted-foreground">0</div>
                <div className="text-sm text-muted-foreground">sessions</div>
                <p className="text-xs text-muted-foreground mt-2">No session data available</p>
              </div>
            ) : (
              <div className="relative h-60 w-60">
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <div className="text-4xl font-bold">{sessionData.total}</div>
                    <div className="text-sm text-muted-foreground">sessions</div>
                  </div>
                </div>
                <svg className="h-full w-full" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="54" fill="none" stroke="hsl(var(--muted))" strokeWidth="12" />
                  {successPercentage > 0 && (
                    <circle
                      cx="60"
                      cy="60"
                      r="54"
                      fill="none"
                      stroke="hsl(var(--primary))"
                      strokeWidth="12"
                      strokeDasharray={`${(successPercentage / 100) * 339.3} 339.3`}
                      strokeDashoffset="0"
                      transform="rotate(-90 60 60)"
                    />
                  )}
                  {failedPercentage > 0 && (
                    <circle
                      cx="60"
                      cy="60"
                      r="54"
                      fill="none"
                      stroke="hsl(var(--destructive))"
                      strokeWidth="12"
                      strokeDasharray={`${(failedPercentage / 100) * 339.3} 339.3`}
                      strokeDashoffset={`-${(successPercentage / 100) * 339.3}`}
                      transform="rotate(-90 60 60)"
                    />
                  )}
                </svg>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <FailedSessionsChart />
        <Card>
          <CardHeader>
            <CardTitle>Session Performance</CardTitle>
            <CardDescription>Key metrics overview</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Success Rate</span>
                <span className="font-medium">{successPercentage.toFixed(1)}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Total Sessions</span>
                <span className="font-medium">{sessionData.total}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Failed Sessions</span>
                <span className="font-medium">{sessionData.failed}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Pending Sessions</span>
                <span className="font-medium">{sessionData.pending}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
