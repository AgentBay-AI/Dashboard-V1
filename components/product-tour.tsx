"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { BarChart3, Shield, DollarSign, MessageSquare, ChevronLeft, ChevronRight } from "lucide-react"

const tourSteps = [
  {
    id: "dashboard",
    title: "Comprehensive Dashboard",
    description:
      "Get a bird's-eye view of all your AI agents with real-time metrics, performance indicators, and health status at a glance.",
    icon: BarChart3,
    image: "/placeholder.svg?height=400&width=600&text=Dashboard+Overview",
    features: ["Real-time metrics", "Performance tracking", "Health monitoring", "Custom alerts"],
  },
  {
    id: "security",
    title: "Advanced Security Monitoring",
    description:
      "Protect your AI infrastructure with comprehensive security scanning, threat detection, and compliance monitoring.",
    icon: Shield,
    image: "/placeholder.svg?height=400&width=600&text=Security+Dashboard",
    features: ["Threat detection", "Compliance monitoring", "Security scoring", "Audit trails"],
  },
  {
    id: "cost",
    title: "Intelligent Cost Management",
    description:
      "Track and optimize your AI spending with detailed cost breakdowns, usage analytics, and budget alerts.",
    icon: DollarSign,
    image: "/placeholder.svg?height=400&width=600&text=Cost+Analytics",
    features: ["Cost tracking", "Budget alerts", "Usage optimization", "Provider comparison"],
  },
  {
    id: "conversations",
    title: "Conversation Analytics",
    description: "Analyze user interactions, conversation flows, and agent performance to improve user experience.",
    icon: MessageSquare,
    image: "/placeholder.svg?height=400&width=600&text=Conversation+Analytics",
    features: ["Interaction analysis", "Flow optimization", "User satisfaction", "Response quality"],
  },
]

export function ProductTour() {
  const [currentStep, setCurrentStep] = useState(0)

  const nextStep = () => {
    setCurrentStep((prev) => (prev + 1) % tourSteps.length)
  }

  const prevStep = () => {
    setCurrentStep((prev) => (prev - 1 + tourSteps.length) % tourSteps.length)
  }

  const currentTour = tourSteps[currentStep]
  const Icon = currentTour.icon

  return (
    <section className="py-20 sm:py-32">
      <div className="container">
        <div className="mx-auto max-w-2xl text-center mb-16">
          <Badge variant="outline" className="mb-4">
            Product Tour
          </Badge>
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl mb-4">
            Everything you need to manage your AI agents
          </h2>
          <p className="text-lg text-muted-foreground">
            Discover how Nexus helps you monitor, secure, and optimize your AI infrastructure
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Content */}
          <div className="space-y-6">
            <div className="flex items-center space-x-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Icon className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="text-2xl font-bold">{currentTour.title}</h3>
                <p className="text-muted-foreground">
                  Step {currentStep + 1} of {tourSteps.length}
                </p>
              </div>
            </div>

            <p className="text-lg text-muted-foreground">{currentTour.description}</p>

            <div className="space-y-3">
              {currentTour.features.map((feature, index) => (
                <div key={index} className="flex items-center space-x-3">
                  <div className="h-2 w-2 rounded-full bg-primary" />
                  <span className="text-sm font-medium">{feature}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center space-x-4 pt-4">
              <Button variant="outline" size="sm" onClick={prevStep}>
                <ChevronLeft className="h-4 w-4 mr-1" />
                Previous
              </Button>
              <Button size="sm" onClick={nextStep}>
                Next
                <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
              <div className="flex space-x-2 ml-4">
                {tourSteps.map((_, index) => (
                  <button
                    key={index}
                    className={`h-2 w-2 rounded-full transition-colors ${
                      index === currentStep ? "bg-primary" : "bg-muted"
                    }`}
                    onClick={() => setCurrentStep(index)}
                  />
                ))}
              </div>
            </div>
          </div>

          {/* Image */}
          <div className="relative">
            <Card className="overflow-hidden">
              <CardContent className="p-0">
                <img
                  src={currentTour.image || "/placeholder.svg"}
                  alt={currentTour.title}
                  className="w-full h-auto object-cover"
                />
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  )
}
