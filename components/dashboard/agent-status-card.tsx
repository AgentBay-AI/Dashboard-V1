import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface AgentStatusCardProps {
  title: string
  value: string
  description?: string
  variant?: "default" | "success" | "warning" | "danger"
}

export function AgentStatusCard({ title, value, description, variant = "default" }: AgentStatusCardProps) {
  const getVariantClasses = () => {
    switch (variant) {
      case "success":
        return "text-green-500"
      case "warning":
        return "text-amber-500"
      case "danger":
        return "text-red-500"
      default:
        return ""
    }
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${getVariantClasses()}`}>{value}</div>
        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
      </CardContent>
    </Card>
  )
}
