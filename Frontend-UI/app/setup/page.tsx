"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { useAgent } from "@/components/agent-provider"
import { ArrowLeft, Building2, Bot, CheckCircle, Circle, ArrowRight } from "lucide-react"

// New Minimalistic Nexus Logo with Glowing Square
function NexusLogo({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="glowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: "#3b82f6", stopOpacity: 0.8 }} />
          <stop offset="25%" style={{ stopColor: "#8b5cf6", stopOpacity: 0.8 }} />
          <stop offset="50%" style={{ stopColor: "#06b6d4", stopOpacity: 0.8 }} />
          <stop offset="75%" style={{ stopColor: "#10b981", stopOpacity: 0.8 }} />
          <stop offset="100%" style={{ stopColor: "#f59e0b", stopOpacity: 0.8 }} />
        </linearGradient>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="innerGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <rect x="8" y="8" width="24" height="24" rx="4" fill="url(#glowGradient)" filter="url(#glow)" opacity="0.6">
        <animate attributeName="opacity" values="0.4;0.8;0.4" dur="3s" repeatCount="indefinite" />
      </rect>

      <rect
        x="10"
        y="10"
        width="20"
        height="20"
        rx="2"
        fill="none"
        stroke="url(#glowGradient)"
        strokeWidth="1"
        filter="url(#innerGlow)"
        opacity="0.8"
      />

      <text
        x="20"
        y="26"
        textAnchor="middle"
        fontSize="16"
        fontWeight="700"
        fontFamily="system-ui, -apple-system, sans-serif"
        fill="white"
        filter="url(#innerGlow)"
      >
        N
      </text>
    </svg>
  )
}

type SetupType = "organization" | "agent"
type AgentType = "custom" | "nocode"

const industries = [
  "Technology",
  "Healthcare",
  "Finance",
  "Education",
  "E-commerce",
  "Manufacturing",
  "Real Estate",
  "Media",
  "Other",
]

const noCodePlatforms = [
  { id: "zapier", name: "Zapier", description: "Workflow automation platform" },
  { id: "make", name: "Make (Integromat)", description: "Visual automation platform" },
  { id: "bubble", name: "Bubble", description: "No-code app development" },
  { id: "webflow", name: "Webflow", description: "Visual web development" },
  { id: "airtable", name: "Airtable", description: "Database and workflow platform" },
  { id: "notion", name: "Notion", description: "Workspace and automation" },
]

const frameworks = [
  { id: "langchain", name: "LangChain", description: "Python/JS framework for LLM applications" },
  { id: "llamaindex", name: "LlamaIndex", description: "Data framework for LLM applications" },
  { id: "haystack", name: "Haystack", description: "End-to-end NLP framework" },
  { id: "semantic-kernel", name: "Semantic Kernel", description: "Microsoft's AI orchestration SDK" },
  { id: "autogen", name: "AutoGen", description: "Multi-agent conversation framework" },
  { id: "crewai", name: "CrewAI", description: "Multi-agent systems framework" },
  { id: "custom", name: "Custom Framework", description: "Your own implementation" },
]

const providers = [
  { id: "openai", name: "OpenAI", models: ["GPT-4", "GPT-3.5", "GPT-4 Turbo"] },
  { id: "anthropic", name: "Anthropic", models: ["Claude 3", "Claude 2", "Claude Instant"] },
  { id: "google", name: "Google", models: ["Gemini Pro", "Gemini Ultra", "PaLM 2"] },
  { id: "cohere", name: "Cohere", models: ["Command", "Command Light", "Embed"] },
  { id: "huggingface", name: "Hugging Face", models: ["Various Open Source Models"] },
  { id: "azure", name: "Azure OpenAI", models: ["GPT-4", "GPT-3.5", "Embeddings"] },
  { id: "aws", name: "AWS Bedrock", models: ["Claude", "Jurassic", "Titan"] },
]

export default function SetupPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { addOrganization, addAgent, organizations } = useAgent()

  const [setupType, setSetupType] = useState<SetupType>("organization")
  const [agentType, setAgentType] = useState<AgentType>("custom")
  const [currentStep, setCurrentStep] = useState(1)
  const [isLoading, setIsLoading] = useState(false)

  // Organization form data
  const [orgData, setOrgData] = useState({
    name: "",
    industry: "",
    description: "",
  })

  // Agent form data
  const [agentData, setAgentData] = useState({
    name: "",
    description: "",
    organizationId: "",
    framework: "",
    provider: "",
    model: "",
    apiKey: "",
    endpoint: "",
    noCodePlatform: "",
  })

  // Handle URL parameters safely
  useEffect(() => {
    if (searchParams) {
      const type = searchParams.get("type")
      if (type === "organization" || type === "agent") {
        setSetupType(type)
      }
    }
  }, [searchParams])

  const handleOrgSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      const newOrg = {
        id: Date.now().toString(),
        name: orgData.name,
        industry: orgData.industry,
        description: orgData.description,
        createdAt: new Date().toISOString(),
      }

      addOrganization(newOrg)
      router.push("/dashboard")
    } catch (error) {
      console.error("Error creating organization:", error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleAgentSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      const newAgent = {
        id: Date.now().toString(),
        name: agentData.name,
        description: agentData.description,
        organizationId: agentData.organizationId,
        framework: agentType === "nocode" ? agentData.noCodePlatform : agentData.framework,
        provider: agentData.provider,
        model: agentData.model,
        status: "active" as const,
        createdAt: new Date().toISOString(),
        agentType,
      }

      addAgent(newAgent)
      router.push("/dashboard")
    } catch (error) {
      console.error("Error creating agent:", error)
    } finally {
      setIsLoading(false)
    }
  }

  const nextStep = () => {
    if (agentType === "nocode" && currentStep === 2) {
      setCurrentStep(4) // Skip framework selection for no-code
    } else {
      setCurrentStep(currentStep + 1)
    }
  }

  const prevStep = () => {
    if (agentType === "nocode" && currentStep === 4) {
      setCurrentStep(2) // Skip back to agent type selection
    } else {
      setCurrentStep(currentStep - 1)
    }
  }

  const getStepTitle = () => {
    if (setupType === "organization") return "Create Organization"

    switch (currentStep) {
      case 1:
        return "Agent Details"
      case 2:
        return "Agent Type"
      case 3:
        return "Framework Selection"
      case 4:
        return "Provider Configuration"
      default:
        return "Setup"
    }
  }

  const getStepDescription = () => {
    if (setupType === "organization") return "Set up a new organization to manage your AI agents"

    switch (currentStep) {
      case 1:
        return "Basic information about your AI agent"
      case 2:
        return "Choose whether your agent is custom-coded or built with no-code tools"
      case 3:
        return "Select the framework your agent is built with"
      case 4:
        return "Configure your AI provider and model"
      default:
        return ""
    }
  }

  if (setupType === "organization") {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-6">
        <div className="max-w-2xl mx-auto">
          <div className="mb-8">
            <Button variant="ghost" onClick={() => router.back()} className="mb-4">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
            <div className="flex items-center space-x-3 mb-2">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/20">
                <NexusLogo className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-3xl font-bold">{getStepTitle()}</h1>
                <p className="text-muted-foreground">{getStepDescription()}</p>
              </div>
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Organization Information</CardTitle>
              <CardDescription>Provide basic information about your organization</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleOrgSubmit} className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="org-name">Organization Name</Label>
                  <Input
                    id="org-name"
                    placeholder="Enter organization name"
                    value={orgData.name}
                    onChange={(e) => setOrgData({ ...orgData, name: e.target.value })}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="industry">Industry</Label>
                  <Select
                    value={orgData.industry}
                    onValueChange={(value) => setOrgData({ ...orgData, industry: value })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select industry" />
                    </SelectTrigger>
                    <SelectContent>
                      {industries.map((industry) => (
                        <SelectItem key={industry} value={industry.toLowerCase()}>
                          {industry}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description (Optional)</Label>
                  <Textarea
                    id="description"
                    placeholder="Brief description of your organization"
                    value={orgData.description}
                    onChange={(e) => setOrgData({ ...orgData, description: e.target.value })}
                    rows={3}
                  />
                </div>

                <Button type="submit" className="w-full" disabled={isLoading || !orgData.name || !orgData.industry}>
                  {isLoading ? "Creating..." : "Create Organization"}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  // Agent setup flow
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-6">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <Button variant="ghost" onClick={() => router.back()} className="mb-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
          <div className="flex items-center space-x-3 mb-6">
            <div className="p-2 rounded-lg bg-green-100 dark:bg-green-900/20">
              <NexusLogo className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">{getStepTitle()}</h1>
              <p className="text-muted-foreground">{getStepDescription()}</p>
            </div>
          </div>

          {/* Progress Steps */}
          <div className="flex items-center space-x-4 mb-8">
            {[1, 2, 3, 4].map((step) => {
              const isActive = step === currentStep
              const isCompleted = step < currentStep
              const isSkipped = agentType === "nocode" && step === 3

              return (
                <div key={step} className="flex items-center">
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-full border-2 ${
                      isCompleted
                        ? "bg-green-500 border-green-500 text-white"
                        : isActive
                          ? "border-blue-500 text-blue-500"
                          : isSkipped
                            ? "border-gray-300 text-gray-300"
                            : "border-gray-300 text-gray-400"
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle className="h-4 w-4" />
                    ) : (
                      <span className="text-sm font-medium">{step}</span>
                    )}
                  </div>
                  {step < 4 && (
                    <div className={`w-12 h-0.5 mx-2 ${step < currentStep ? "bg-green-500" : "bg-gray-300"}`} />
                  )}
                </div>
              )
            })}
          </div>
        </div>

        <Card>
          <CardContent className="p-8">
            {currentStep === 1 && (
              <div className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="agent-name">Agent Name</Label>
                  <Input
                    id="agent-name"
                    placeholder="Enter agent name"
                    value={agentData.name}
                    onChange={(e) => setAgentData({ ...agentData, name: e.target.value })}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="organization">Organization</Label>
                  <Select
                    value={agentData.organizationId}
                    onValueChange={(value) => setAgentData({ ...agentData, organizationId: value })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
                      {organizations.map((org) => (
                        <SelectItem key={org.id} value={org.id}>
                          {org.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="agent-description">Description</Label>
                  <Textarea
                    id="agent-description"
                    placeholder="Brief description of your agent's purpose"
                    value={agentData.description}
                    onChange={(e) => setAgentData({ ...agentData, description: e.target.value })}
                    rows={3}
                  />
                </div>

                <div className="flex justify-end">
                  <Button onClick={nextStep} disabled={!agentData.name || !agentData.organizationId}>
                    Next Step
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {currentStep === 2 && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-4">What type of agent are you setting up?</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card
                      className={`cursor-pointer transition-all ${
                        agentType === "custom"
                          ? "ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950/20"
                          : "hover:bg-slate-50 dark:hover:bg-slate-800"
                      }`}
                      onClick={() => setAgentType("custom")}
                    >
                      <CardContent className="p-6">
                        <div className="flex items-center space-x-3 mb-3">
                          <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/20">
                            <Bot className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                          </div>
                          <h4 className="font-semibold">Custom-Coded Agent</h4>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Built with frameworks like LangChain, LlamaIndex, or custom implementations
                        </p>
                      </CardContent>
                    </Card>

                    <Card
                      className={`cursor-pointer transition-all ${
                        agentType === "nocode"
                          ? "ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950/20"
                          : "hover:bg-slate-50 dark:hover:bg-slate-800"
                      }`}
                      onClick={() => setAgentType("nocode")}
                    >
                      <CardContent className="p-6">
                        <div className="flex items-center space-x-3 mb-3">
                          <div className="p-2 rounded-lg bg-green-100 dark:bg-green-900/20">
                            <Building2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                          </div>
                          <h4 className="font-semibold">No-Code Agent</h4>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Built with no-code platforms like Zapier, Make, or Bubble
                        </p>
                      </CardContent>
                    </Card>
                  </div>
                </div>

                <div className="flex justify-between">
                  <Button variant="outline" onClick={prevStep}>
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Previous
                  </Button>
                  <Button onClick={nextStep}>
                    Next Step
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {currentStep === 3 && agentType === "custom" && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-4">Select Framework</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {frameworks.map((framework) => (
                      <Card
                        key={framework.id}
                        className={`cursor-pointer transition-all ${
                          agentData.framework === framework.id
                            ? "ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950/20"
                            : "hover:bg-slate-50 dark:hover:bg-slate-800"
                        }`}
                        onClick={() => setAgentData({ ...agentData, framework: framework.id })}
                      >
                        <CardContent className="p-4">
                          <div className="flex items-start space-x-3">
                            <Circle
                              className={`h-4 w-4 mt-1 ${
                                agentData.framework === framework.id ? "text-blue-500 fill-current" : "text-gray-400"
                              }`}
                            />
                            <div>
                              <h4 className="font-semibold">{framework.name}</h4>
                              <p className="text-sm text-muted-foreground">{framework.description}</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>

                <div className="flex justify-between">
                  <Button variant="outline" onClick={prevStep}>
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Previous
                  </Button>
                  <Button onClick={nextStep} disabled={!agentData.framework}>
                    Next Step
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {currentStep === 4 && (
              <div className="space-y-6">
                {agentType === "nocode" ? (
                  <div>
                    <h3 className="text-lg font-semibold mb-4">Select No-Code Platform</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      {noCodePlatforms.map((platform) => (
                        <Card
                          key={platform.id}
                          className={`cursor-pointer transition-all ${
                            agentData.noCodePlatform === platform.id
                              ? "ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950/20"
                              : "hover:bg-slate-50 dark:hover:bg-slate-800"
                          }`}
                          onClick={() => setAgentData({ ...agentData, noCodePlatform: platform.id })}
                        >
                          <CardContent className="p-4">
                            <div className="flex items-start space-x-3">
                              <Circle
                                className={`h-4 w-4 mt-1 ${
                                  agentData.noCodePlatform === platform.id
                                    ? "text-blue-500 fill-current"
                                    : "text-gray-400"
                                }`}
                              />
                              <div>
                                <h4 className="font-semibold">{platform.name}</h4>
                                <p className="text-sm text-muted-foreground">{platform.description}</p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </div>
                ) : null}

                <div>
                  <h3 className="text-lg font-semibold mb-4">AI Provider Configuration</h3>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="provider">AI Provider</Label>
                      <Select
                        value={agentData.provider}
                        onValueChange={(value) => setAgentData({ ...agentData, provider: value, model: "" })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select AI provider" />
                        </SelectTrigger>
                        <SelectContent>
                          {providers.map((provider) => (
                            <SelectItem key={provider.id} value={provider.id}>
                              {provider.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {agentData.provider && (
                      <div className="space-y-2">
                        <Label htmlFor="model">Model</Label>
                        <Select
                          value={agentData.model}
                          onValueChange={(value) => setAgentData({ ...agentData, model: value })}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select model" />
                          </SelectTrigger>
                          <SelectContent>
                            {providers
                              .find((p) => p.id === agentData.provider)
                              ?.models.map((model) => (
                                <SelectItem key={model} value={model.toLowerCase().replace(/\s+/g, "-")}>
                                  {model}
                                </SelectItem>
                              ))}
                          </SelectContent>
                        </Select>
                      </div>
                    )}

                    <div className="space-y-2">
                      <Label htmlFor="api-key">API Key</Label>
                      <Input
                        id="api-key"
                        type="password"
                        placeholder="Enter your API key"
                        value={agentData.apiKey}
                        onChange={(e) => setAgentData({ ...agentData, apiKey: e.target.value })}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="endpoint">Custom Endpoint (Optional)</Label>
                      <Input
                        id="endpoint"
                        placeholder="https://api.example.com/v1"
                        value={agentData.endpoint}
                        onChange={(e) => setAgentData({ ...agentData, endpoint: e.target.value })}
                      />
                    </div>
                  </div>
                </div>

                <div className="flex justify-between">
                  <Button variant="outline" onClick={prevStep}>
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Previous
                  </Button>
                  <Button
                    onClick={handleAgentSubmit}
                    disabled={
                      isLoading ||
                      !agentData.provider ||
                      !agentData.model ||
                      (agentType === "nocode" && !agentData.noCodePlatform)
                    }
                  >
                    {isLoading ? "Creating..." : "Create Agent"}
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
