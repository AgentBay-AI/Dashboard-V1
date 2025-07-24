"use client"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Check, Zap, Building2, Crown, ArrowRight } from "lucide-react"

export function PricingSection() {
  const plans = [
    {
      name: "Starter",
      description: "Perfect for small teams getting started with AI monitoring",
      price: "$29",
      period: "/month",
      features: [
        "Up to 5 AI agents",
        "Basic performance monitoring",
        "Email notifications",
        "7-day data retention",
        "Community support",
        "Basic security scanning",
      ],
      cta: "Start Free Trial",
      popular: false,
      available: true,
      icon: Zap,
    },
    {
      name: "Professional",
      description: "Advanced monitoring for growing teams and businesses",
      price: "$99",
      period: "/month",
      features: [
        "Up to 25 AI agents",
        "Advanced analytics & insights",
        "Real-time alerts & notifications",
        "30-day data retention",
        "Priority support",
        "Advanced security compliance",
        "Custom integrations",
        "Team collaboration tools",
      ],
      cta: "Coming Soon",
      popular: true,
      available: false,
      icon: Building2,
    },
    {
      name: "Enterprise",
      description: "Complete solution for large organizations",
      price: "$299",
      period: "/month",
      features: [
        "Unlimited AI agents",
        "Enterprise-grade analytics",
        "24/7 monitoring & support",
        "Unlimited data retention",
        "Dedicated account manager",
        "Advanced security & compliance",
        "Custom integrations & APIs",
        "White-label options",
        "SLA guarantees",
      ],
      cta: "Contact Sales",
      popular: false,
      available: true,
      icon: Crown,
    },
    {
      name: "Custom",
      description: "Tailored solutions for unique requirements",
      price: "Custom",
      period: "pricing",
      features: [
        "Fully customized solution",
        "Dedicated infrastructure",
        "Custom feature development",
        "On-premise deployment options",
        "24/7 dedicated support",
        "Custom SLA agreements",
        "Advanced security auditing",
        "Training & onboarding",
      ],
      cta: "Coming Soon",
      popular: false,
      available: false,
      icon: Crown,
    },
  ]

  return (
    <section className="py-24 bg-gradient-to-b from-background to-muted/20">
      <div className="container px-4 md:px-6">
        <div className="text-center mb-16">
          <Badge variant="secondary" className="mb-4">
            Pricing Plans
          </Badge>
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl mb-4">Choose the Perfect Plan for Your Team</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Start monitoring your AI agents today with our flexible pricing options. Scale as you grow.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-4 max-w-7xl mx-auto">
          {plans.map((plan) => {
            const Icon = plan.icon
            return (
              <Card
                key={plan.name}
                className={`relative overflow-hidden transition-all duration-300 hover:shadow-lg ${
                  plan.popular
                    ? "border-primary shadow-lg scale-105"
                    : plan.available
                      ? "hover:border-primary/50"
                      : "opacity-75"
                }`}
              >
                {plan.popular && (
                  <div className="absolute top-0 left-0 right-0 bg-primary text-primary-foreground text-center py-2 text-sm font-medium">
                    Most Popular
                  </div>
                )}

                {!plan.available && (
                  <div className="absolute top-4 right-4">
                    <Badge
                      variant="secondary"
                      className="bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
                    >
                      Coming Soon
                    </Badge>
                  </div>
                )}

                <CardHeader className={plan.popular ? "pt-8" : ""}>
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className="h-5 w-5 text-primary" />
                    <CardTitle className="text-xl">{plan.name}</CardTitle>
                  </div>
                  <CardDescription className="text-sm">{plan.description}</CardDescription>
                  <div className="flex items-baseline gap-1 mt-4">
                    <span className="text-3xl font-bold">{plan.price}</span>
                    <span className="text-muted-foreground">{plan.period}</span>
                  </div>
                </CardHeader>

                <CardContent>
                  <ul className="space-y-3">
                    {plan.features.map((feature, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <Check className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                        <span className="text-sm">{feature}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>

                <CardFooter>
                  <Button
                    className={`w-full ${
                      plan.popular
                        ? "bg-primary hover:bg-primary/90"
                        : plan.available
                          ? "bg-primary hover:bg-primary/90"
                          : "bg-muted text-muted-foreground cursor-not-allowed"
                    }`}
                    disabled={!plan.available}
                  >
                    {plan.available ? (
                      <>
                        {plan.cta}
                        <ArrowRight className="ml-2 h-4 w-4" />
                      </>
                    ) : (
                      plan.cta
                    )}
                  </Button>
                </CardFooter>
              </Card>
            )
          })}
        </div>

        <div className="text-center mt-16">
          <p className="text-muted-foreground mb-4">All plans include a 14-day free trial. No credit card required.</p>
          <div className="flex items-center justify-center gap-8 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <Check className="h-4 w-4 text-primary" />
              <span>Cancel anytime</span>
            </div>
            <div className="flex items-center gap-2">
              <Check className="h-4 w-4 text-primary" />
              <span>24/7 support</span>
            </div>
            <div className="flex items-center gap-2">
              <Check className="h-4 w-4 text-primary" />
              <span>SOC 2 compliant</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
