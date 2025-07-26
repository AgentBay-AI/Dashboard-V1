"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield } from "lucide-react"

export function RiskAssessment() {
  const [riskData, setRiskData] = useState({
    level: "Low",
    change: "0%",
    risks: [
      { level: "High", value: 0 },
      { level: "Medium", value: 0 },
      { level: "Low", value: 0 },
    ]
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchRiskData = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/risk-assessment', {
          signal: AbortSignal.timeout(5000)
        })
        if (response.ok) {
          const result = await response.json()
          setRiskData(result.data || {
            level: "Low",
            change: "0%",
            risks: [
              { level: "High", value: 0 },
              { level: "Medium", value: 0 },
              { level: "Low", value: 0 },
            ]
          })
        }
      } catch (error) {
        console.error('Failed to fetch risk data:', error)
        // Keep zero state
      } finally {
        setLoading(false)
      }
    }

    fetchRiskData()
  }, [])

  const hasRiskData = riskData.risks.some(risk => risk.value > 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Assessment</CardTitle>
        <CardDescription>Current {riskData.change}</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-32 flex items-center justify-center">
            <div className="text-sm text-muted-foreground">Loading risk assessment...</div>
          </div>
        ) : !hasRiskData ? (
          <div className="text-center py-8">
            <Shield className="h-12 w-12 text-emerald-500 mx-auto mb-3" />
            <div className="text-3xl font-bold text-emerald-600">No Risks</div>
            <p className="text-sm text-muted-foreground mt-2">No risk data available</p>
          </div>
        ) : (
          <>
            <div className="text-3xl font-bold">{riskData.level}</div>
            <div className="mt-6 space-y-4">
              {riskData.risks.map((risk) => (
                <div key={risk.level} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">{risk.level}</div>
                    <div className="text-sm text-muted-foreground">{risk.value}%</div>
                  </div>
                  <div className="h-3 w-full overflow-hidden rounded-full bg-secondary">
                    <div 
                      className="h-full bg-primary/70 transition-all duration-500" 
                      style={{ width: `${risk.value}%` }} 
                    />
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
