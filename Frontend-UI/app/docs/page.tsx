import { LandingHeader } from "@/components/landing-header"
import { LandingFooter } from "@/components/landing-footer"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { BookOpen, Code, Zap, Shield, BarChart, Settings } from "lucide-react"

export default function DocsPage() {
  const sections = [
    {
      title: "Getting Started",
      description: "Quick start guide to set up your first AI agent monitoring",
      icon: Zap,
      articles: [
        "Installation & Setup",
        "Creating Your First Agent",
        "Basic Configuration",
        "Understanding the Dashboard",
      ],
      badge: "Beginner",
    },
    {
      title: "API Reference",
      description: "Complete API documentation for integrating with Nexus",
      icon: Code,
      articles: ["Authentication", "Agent Management API", "Monitoring Endpoints", "Webhook Configuration"],
      badge: "Developer",
    },
    {
      title: "Security & Compliance",
      description: "Security best practices and compliance guidelines",
      icon: Shield,
      articles: ["Security Overview", "Data Encryption", "Access Controls", "Compliance Standards"],
      badge: "Security",
    },
    {
      title: "Analytics & Reporting",
      description: "Understanding metrics, reports, and data visualization",
      icon: BarChart,
      articles: ["Performance Metrics", "Custom Dashboards", "Report Generation", "Data Export"],
      badge: "Analytics",
    },
    {
      title: "Configuration",
      description: "Advanced configuration and customization options",
      icon: Settings,
      articles: ["Environment Setup", "Custom Integrations", "Alert Configuration", "User Management"],
      badge: "Advanced",
    },
    {
      title: "Guides & Tutorials",
      description: "Step-by-step guides for common use cases",
      icon: BookOpen,
      articles: ["Multi-Agent Setup", "Cost Optimization", "Troubleshooting", "Best Practices"],
      badge: "Tutorial",
    },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-background/95">
      <LandingHeader />
      <main className="container mx-auto px-4 py-12">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold tracking-tight mb-4">Documentation</h1>
            <p className="text-xl text-muted-foreground">
              Everything you need to know about using Nexus AI monitoring platform
            </p>
          </div>

          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {sections.map((section, index) => {
              const Icon = section.icon
              return (
                <Card key={index} className="cursor-pointer hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="flex items-center justify-between mb-2">
                      <Icon className="h-8 w-8 text-primary" />
                      <Badge variant="outline">{section.badge}</Badge>
                    </div>
                    <CardTitle className="text-xl">{section.title}</CardTitle>
                    <CardDescription>{section.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2">
                      {section.articles.map((article, articleIndex) => (
                        <li
                          key={articleIndex}
                          className="text-sm text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
                        >
                          • {article}
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              )
            })}
          </div>

          <div className="mt-16 text-center">
            <Card className="max-w-2xl mx-auto">
              <CardHeader>
                <CardTitle>Need Help?</CardTitle>
                <CardDescription>Can't find what you're looking for? Our support team is here to help.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col sm:flex-row gap-4 justify-center">
                <button className="px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors">
                  Contact Support
                </button>
                <button className="px-6 py-2 border border-border rounded-md hover:bg-accent transition-colors">
                  Join Community
                </button>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
      <LandingFooter />
    </div>
  )
}
