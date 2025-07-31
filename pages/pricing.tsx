import { LandingHeader } from "@/components/landing-header"
import { LandingFooter } from "@/components/landing-footer"
import { PricingSection } from "@/components/pricing-section"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Check, X } from "lucide-react"

export default function PricingPage() {
  const features = [
    {
      feature: "AI Agents Monitored",
      starter: "5",
      professional: "25",
      enterprise: "Unlimited",
      custom: "Unlimited",
    },
    {
      feature: "Real-time Monitoring",
      starter: true,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Basic Analytics",
      starter: true,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Email Support",
      starter: true,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Advanced Analytics",
      starter: false,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Priority Support",
      starter: false,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Custom Integrations",
      starter: false,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Security Scanning",
      starter: false,
      professional: true,
      enterprise: true,
      custom: true,
    },
    {
      feature: "White-label Options",
      starter: false,
      professional: false,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Dedicated Support",
      starter: false,
      professional: false,
      enterprise: true,
      custom: true,
    },
    {
      feature: "Advanced Compliance",
      starter: false,
      professional: false,
      enterprise: true,
      custom: true,
    },
    {
      feature: "On-premise Deployment",
      starter: false,
      professional: false,
      enterprise: false,
      custom: true,
    },
    {
      feature: "SLA Guarantees",
      starter: false,
      professional: false,
      enterprise: false,
      custom: true,
    },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-background/95">
      <LandingHeader />
      <main className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold tracking-tight mb-4">Pricing Plans</h1>
          <p className="text-xl text-muted-foreground">Choose the perfect plan for your AI monitoring needs</p>
        </div>

        <PricingSection />

        <div className="mt-16">
          <h2 className="text-3xl font-bold text-center mb-8">Feature Comparison</h2>
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b">
                    <th className="text-left p-4 font-medium">Features</th>
                    <th className="text-center p-4 font-medium">Starter</th>
                    <th className="text-center p-4 font-medium">Professional</th>
                    <th className="text-center p-4 font-medium">Enterprise</th>
                    <th className="text-center p-4 font-medium">Custom</th>
                  </tr>
                </thead>
                <tbody>
                  {features.map((row, index) => (
                    <tr key={index} className="border-b hover:bg-accent/50">
                      <td className="p-4 font-medium">{row.feature}</td>
                      <td className="p-4 text-center">
                        {typeof row.starter === "boolean" ? (
                          row.starter ? (
                            <Check className="h-5 w-5 text-green-500 mx-auto" />
                          ) : (
                            <X className="h-5 w-5 text-red-500 mx-auto" />
                          )
                        ) : (
                          row.starter
                        )}
                      </td>
                      <td className="p-4 text-center">
                        {typeof row.professional === "boolean" ? (
                          row.professional ? (
                            <Check className="h-5 w-5 text-green-500 mx-auto" />
                          ) : (
                            <X className="h-5 w-5 text-red-500 mx-auto" />
                          )
                        ) : (
                          row.professional
                        )}
                      </td>
                      <td className="p-4 text-center">
                        {typeof row.enterprise === "boolean" ? (
                          row.enterprise ? (
                            <Check className="h-5 w-5 text-green-500 mx-auto" />
                          ) : (
                            <X className="h-5 w-5 text-red-500 mx-auto" />
                          )
                        ) : (
                          row.enterprise
                        )}
                      </td>
                      <td className="p-4 text-center">
                        {typeof row.custom === "boolean" ? (
                          row.custom ? (
                            <Check className="h-5 w-5 text-green-500 mx-auto" />
                          ) : (
                            <X className="h-5 w-5 text-red-500 mx-auto" />
                          )
                        ) : (
                          row.custom
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        <div className="mt-16 text-center">
          <Card className="max-w-2xl mx-auto">
            <CardHeader>
              <CardTitle>Enterprise & Custom Solutions</CardTitle>
              <CardDescription>
                Need a tailored solution for your organization? Our enterprise team can help you design the perfect
                monitoring setup.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <button className="px-8 py-3 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors">
                Contact Sales Team
              </button>
            </CardContent>
          </Card>
        </div>
      </main>
      <LandingFooter />
    </div>
  )
}
