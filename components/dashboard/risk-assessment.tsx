import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export function RiskAssessment() {
  const risks = [
    { level: "High", value: 65 },
    { level: "Medium", value: 85 },
    { level: "Low", value: 40 },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Assessment</CardTitle>
        <CardDescription>Current +10%</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold">Medium</div>
        <div className="mt-6 space-y-4">
          {risks.map((risk) => (
            <div key={risk.level} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">{risk.level}</div>
              </div>
              <div className="h-3 w-full overflow-hidden rounded-full bg-secondary">
                <div className="h-full bg-primary/70" style={{ width: `${risk.value}%` }} />
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
