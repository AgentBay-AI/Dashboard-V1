import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { RiskAssessment } from "@/components/dashboard/risk-assessment"
import { SessionHistoryChart } from "@/components/dashboard/session-history-chart"
import { FailedSessionsChart } from "@/components/dashboard/failed-sessions-chart"

export default function AnalysisPage() {
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
            <div className="relative h-60 w-60">
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-4xl font-bold">225</div>
                  <div className="text-sm text-muted-foreground">sessions</div>
                </div>
              </div>
              <svg className="h-full w-full" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="54" fill="none" stroke="hsl(var(--muted))" strokeWidth="12" />
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke="hsl(var(--primary))"
                  strokeWidth="12"
                  strokeDasharray="339.3"
                  strokeDashoffset="84.8"
                  transform="rotate(-90 60 60)"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke="hsl(var(--destructive))"
                  strokeWidth="12"
                  strokeDasharray="339.3"
                  strokeDashoffset="305.4"
                  transform="rotate(192 60 60)"
                />
              </svg>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <FailedSessionsChart />
        <Card>
          <CardHeader>
            <CardTitle>Session Cost</CardTitle>
            <CardDescription>Cost per session type</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {/* GPT-4 Sessions */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>GPT-4 Sessions</span>
                  <span>$100.00</span>
                </div>
                <div className="relative h-2 w-full bg-slate-200 dark:bg-slate-700 rounded">
                  <div className="absolute inset-y-0 left-0 bg-blue-500 rounded" style={{ width: "40%" }}></div>
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>1,250 sessions @ $0.08 each</span>
                  <span>40%</span>
                </div>
              </div>

              {/* Claude Sessions */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>Claude Sessions</span>
                  <span>$126.00</span>
                </div>
                <div className="relative h-2 w-full bg-slate-200 dark:bg-slate-700 rounded">
                  <div className="absolute inset-y-0 left-0 bg-purple-500 rounded" style={{ width: "50%" }}></div>
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>2,100 sessions @ $0.06 each</span>
                  <span>50%</span>
                </div>
              </div>

              {/* Gemini Sessions */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>Gemini Sessions</span>
                  <span>$6.00</span>
                </div>
                <div className="relative h-2 w-full bg-slate-200 dark:bg-slate-700 rounded">
                  <div className="absolute inset-y-0 left-0 bg-green-500 rounded" style={{ width: "2%" }}></div>
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>150 sessions @ $0.04 each</span>
                  <span>2%</span>
                </div>
              </div>

              {/* Groq Sessions */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>Groq Sessions</span>
                  <span>$16.00</span>
                </div>
                <div className="relative h-2 w-full bg-slate-200 dark:bg-slate-700 rounded">
                  <div className="absolute inset-y-0 left-0 bg-amber-500 rounded" style={{ width: "6%" }}></div>
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>800 sessions @ $0.02 each</span>
                  <span>6%</span>
                </div>
              </div>

              {/* Mistral Sessions */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>Mistral Sessions</span>
                  <span>$6.00</span>
                </div>
                <div className="relative h-2 w-full bg-slate-200 dark:bg-slate-700 rounded">
                  <div className="absolute inset-y-0 left-0 bg-red-500 rounded" style={{ width: "2%" }}></div>
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>200 sessions @ $0.03 each</span>
                  <span>2%</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
