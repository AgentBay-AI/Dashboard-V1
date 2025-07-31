import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity, AlertTriangle, CheckCircle, DollarSign } from "lucide-react"

export function RecentActivity() {
  const activities = [
    {
      id: 1,
      type: "alert",
      title: "Security Alert Detected",
      description: "Potential prompt injection detected in OpenAI Agent",
      time: "2 hours ago",
      icon: AlertTriangle,
      color: "text-red-500",
    },
    {
      id: 2,
      type: "success",
      title: "Agent Connected Successfully",
      description: "Anthropic Claude Agent is now online",
      time: "5 hours ago",
      icon: CheckCircle,
      color: "text-green-500",
    },
    {
      id: 3,
      type: "cost",
      title: "Monthly Budget Alert",
      description: "You've used 83% of your monthly budget",
      time: "1 day ago",
      icon: DollarSign,
      color: "text-amber-500",
    },
    {
      id: 4,
      type: "activity",
      title: "Performance Spike",
      description: "OpenAI Agent performance increased by 15%",
      time: "2 days ago",
      icon: Activity,
      color: "text-blue-500",
    },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
        <CardDescription>Latest events and notifications</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {activities.map((activity) => {
          const Icon = activity.icon
          return (
            <div
              key={activity.id}
              className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-accent/50 transition-colors"
            >
              <Icon className={`h-5 w-5 mt-0.5 ${activity.color}`} />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm">{activity.title}</p>
                <p className="text-sm text-muted-foreground">{activity.description}</p>
                <p className="text-xs text-muted-foreground mt-1">{activity.time}</p>
              </div>
              <Badge variant="outline" className="text-xs">
                {activity.type}
              </Badge>
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}
