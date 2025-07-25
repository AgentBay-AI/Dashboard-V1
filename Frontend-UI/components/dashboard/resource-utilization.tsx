"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"

export function ResourceUtilization() {
  const [resources, setResources] = useState([
    { name: "CPU", value: 0, label: "CPU" },
    { name: "Memory", value: 0, label: "Memory" },
    { name: "Storage", value: 0, label: "Storage" },
  ])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchResourceData = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/analytics/resource-utilization')
        if (response.ok) {
          const result = await response.json()
          const data = result.data
          setResources([
            { name: "CPU", value: Math.round(data.cpu_usage || 0), label: "CPU" },
            { name: "Memory", value: Math.round(data.memory_usage || 0), label: "Memory" },
            { name: "Storage", value: Math.round(data.disk_usage || 0), label: "Storage" },
          ])
        } else {
          // Show zero state if API fails
          setResources([
            { name: "CPU", value: 0, label: "CPU" },
            { name: "Memory", value: 0, label: "Memory" },
            { name: "Storage", value: 0, label: "Storage" },
          ])
        }
      } catch (error) {
        console.error('Failed to fetch resource data:', error)
        // Show zero state on error - no dummy data
        setResources([
          { name: "CPU", value: 0, label: "CPU" },
          { name: "Memory", value: 0, label: "Memory" },
          { name: "Storage", value: 0, label: "Storage" },
        ])
      } finally {
        setLoading(false)
      }
    }

    fetchResourceData()
  }, [])

  return (
    <Card>
      <CardHeader>
        <CardTitle>Resource Utilization</CardTitle>
        <CardDescription>Last 30 Days -2%</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-8">
          {resources.map((resource) => (
            <div key={resource.name} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">{resource.label}</div>
                <div className="text-sm text-muted-foreground">{resource.value}%</div>
              </div>
              <Progress value={resource.value} className="h-2" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
