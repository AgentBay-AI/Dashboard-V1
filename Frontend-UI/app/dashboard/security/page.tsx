import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { AlertTriangle, CheckCircle } from "lucide-react"

export default function SecurityPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security & Compliance</h1>
        <p className="text-muted-foreground">Monitor security status and compliance of your AI agents.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Compliance Score</CardTitle>
            <CardDescription>Overall compliance with security standards</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-4xl font-bold">98%</div>
            <div className="text-sm font-medium text-green-500">+2%</div>
            <Progress value={98} className="h-2 mt-4" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Security Alerts</CardTitle>
            <CardDescription>Active security issues requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-4xl font-bold">3</div>
            <div className="text-sm font-medium text-red-500">-1</div>
          </CardContent>
        </Card>
      </div>

      <h2 className="text-2xl font-bold tracking-tight">Vulnerability Assessment</h2>
      <div className="space-y-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <CardTitle className="text-base font-medium">Prompt Injection Vulnerability</CardTitle>
            </div>
            <Badge variant="outline">Medium Risk</Badge>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Potential vulnerability to prompt injection attacks detected in agent responses. Implement stronger input
              validation and output filtering.
            </p>
            <div className="mt-4">
              <Progress value={65} className="h-2" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <CardTitle className="text-base font-medium">Data Leakage Risk</CardTitle>
            </div>
            <Badge variant="outline">High Risk</Badge>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Potential data leakage detected in agent responses. Review and implement stronger data handling policies
              and PII filtering.
            </p>
            <div className="mt-4">
              <Progress value={85} className="h-2" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <CardTitle className="text-base font-medium">Authentication Security</CardTitle>
            </div>
            <Badge variant="outline">Secure</Badge>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Authentication mechanisms are properly implemented and secure. Regular key rotation and access controls
              are in place.
            </p>
            <div className="mt-4">
              <Progress value={100} className="h-2" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
