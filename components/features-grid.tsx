"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  BarChart3,
  Shield,
  DollarSign,
  MessageSquare,
  Settings,
  TrendingUp,
  Zap,
  Globe,
  Lock,
  Bell,
  Users,
  Database,
} from "lucide-react"

const features = [
  {
    icon: BarChart3,
    title: "Real-time Analytics",
    description: "Monitor your AI agents with comprehensive dashboards and real-time performance metrics.",
    badge: "Core",
  },
  {
    icon: Shield,
    title: "Security Monitoring",
    description: "Advanced security scanning and threat detection to protect your AI infrastructure.",
    badge: "Security",
  },
  {
    icon: DollarSign,
    title: "Cost Management",
    description: "Track spending, optimize costs, and get detailed breakdowns of your AI usage.",
    badge: "Finance",
  },
  {
    icon: MessageSquare,
    title: "Conversation Analytics",
    description: "Analyze user interactions and improve conversation flows with detailed insights.",
    badge: "Analytics",
  },
  {
    icon: Zap,
    title: "Performance Optimization",
    description: "Identify bottlenecks and optimize your AI agents for better performance.",
    badge: "Performance",
  },
  {
    icon: Globe,
    title: "Multi-Provider Support",
    description: "Connect and monitor AI agents across different providers and platforms.",
    badge: "Integration",
  },
  {
    icon: Lock,
    title: "Compliance & Governance",
    description: "Ensure your AI operations meet regulatory requirements and internal policies.",
    badge: "Compliance",
  },
  {
    icon: Bell,
    title: "Smart Alerts",
    description: "Get notified about important events, anomalies, and performance issues.",
    badge: "Monitoring",
  },
  {
    icon: Users,
    title: "Team Collaboration",
    description: "Share insights, collaborate on optimizations, and manage team access.",
    badge: "Collaboration",
  },
  {
    icon: Database,
    title: "Data Export & API",
    description: "Export your data and integrate with existing tools using our comprehensive API.",
    badge: "Integration",
  },
  {
    icon: TrendingUp,
    title: "Predictive Insights",
    description: "Get AI-powered predictions about performance, costs, and potential issues.",
    badge: "AI",
  },
  {
    icon: Settings,
    title: "Custom Configurations",
    description: "Tailor the platform to your specific needs with flexible configuration options.",
    badge: "Customization",
  },
]

const badgeColors = {
  Core: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  Security: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  Finance: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
  Analytics: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300",
  Performance: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  Integration: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-300",
  Compliance: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  Monitoring: "bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-300",
  Collaboration: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-300",
  AI: "bg-violet-100 text-violet-800 dark:bg-violet-900 dark:text-violet-300",
  Customization: "bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-300",
}

export function FeaturesGrid() {
  return (
    <section className="py-20 sm:py-32 bg-muted/30">
      <div className="container">
        <div className="mx-auto max-w-2xl text-center mb-16">
          <Badge variant="outline" className="mb-4">
            Features
          </Badge>
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl mb-4">Everything you need in one platform</h2>
          <p className="text-lg text-muted-foreground">
            Comprehensive tools and insights to manage your AI agents effectively
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => {
            const Icon = feature.icon
            return (
              <Card key={index} className="relative group hover:shadow-lg transition-all duration-300">
                <CardHeader className="pb-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 group-hover:bg-primary/20 transition-colors">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <Badge
                      variant="secondary"
                      className={`text-xs ${badgeColors[feature.badge as keyof typeof badgeColors] || "bg-gray-100 text-gray-800"}`}
                    >
                      {feature.badge}
                    </Badge>
                  </div>
                  <CardTitle className="text-lg">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm leading-relaxed">{feature.description}</CardDescription>
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>
    </section>
  )
}
