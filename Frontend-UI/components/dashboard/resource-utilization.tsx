"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"

export function ResourceUtilization() {
  const resources = [
    { name: "CPU", value: 65, label: "CPU" },
    { name: "Memory", value: 78, label: "Memory" },
    { name: "Storage", value: 92, label: "Storage" },
  ]

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
