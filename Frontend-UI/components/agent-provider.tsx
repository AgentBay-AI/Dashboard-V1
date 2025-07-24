"use client"

import { createContext, useContext, useState, type ReactNode } from "react"

export interface Organization {
  id: string
  name: string
  industry: string
  createdAt: string
  description?: string
}

export interface Agent {
  id: string
  name: string
  description: string
  organizationId: string
  provider: string
  framework: string
  model: string
  status: "active" | "inactive" | "error"
  lastSync: string
  models: string[]
  apiKey: string
  agentType: "custom" | "nocode"
  createdAt: string
  endpoint?: string
  noCodePlatform?: string
  performance?: number
  cost?: number
  requests?: number
}

interface AgentContextType {
  organizations: Organization[]
  agents: Agent[]
  currentOrganization: Organization | null
  addOrganization: (org: Organization) => void
  setCurrentOrganization: (org: Organization) => void
  addAgent: (agent: Agent) => void
  updateAgent: (id: string, updates: Partial<Agent>) => void
  removeAgent: (id: string) => void
  getAgentsByOrganization: (orgId: string) => Agent[]
}

const AgentContext = createContext<AgentContextType | undefined>(undefined)

export function AgentProvider({ children }: { children: ReactNode }) {
  const [organizations, setOrganizations] = useState<Organization[]>([
    {
      id: "1",
      name: "Acme Inc.",
      industry: "Technology",
      createdAt: new Date().toISOString(),
      description: "Leading technology solutions provider",
    },
  ])

  const [currentOrganization, setCurrentOrganization] = useState<Organization | null>(organizations[0])

  const [agents, setAgents] = useState<Agent[]>([
    {
      id: "1",
      name: "Customer Support Bot",
      description: "Handles customer inquiries and support tickets",
      organizationId: "1",
      provider: "openai",
      framework: "langchain",
      model: "gpt-4",
      status: "active",
      lastSync: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      models: ["gpt-4", "gpt-3.5-turbo"],
      apiKey: "sk-***",
      agentType: "custom",
      createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      performance: 95,
      cost: 850,
      requests: 12450,
    },
    {
      id: "2",
      name: "Content Generator",
      description: "Generates marketing content and blog posts",
      organizationId: "1",
      provider: "anthropic",
      framework: "custom",
      model: "claude-3-opus",
      status: "active",
      lastSync: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      models: ["claude-3-opus"],
      apiKey: "sk_ant-***",
      agentType: "custom",
      createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
      performance: 88,
      cost: 400,
      requests: 5230,
    },
  ])

  const addOrganization = (org: Organization) => {
    setOrganizations((prev) => [...prev, org])
  }

  const addAgent = (agent: Agent) => {
    setAgents((prev) => [...prev, agent])
  }

  const updateAgent = (id: string, updates: Partial<Agent>) => {
    setAgents((prev) => prev.map((agent) => (agent.id === id ? { ...agent, ...updates } : agent)))
  }

  const removeAgent = (id: string) => {
    setAgents((prev) => prev.filter((agent) => agent.id !== id))
  }

  const getAgentsByOrganization = (orgId: string) => {
    return agents.filter((agent) => agent.organizationId === orgId)
  }

  return (
    <AgentContext.Provider
      value={{
        organizations,
        agents,
        currentOrganization,
        addOrganization,
        setCurrentOrganization,
        addAgent,
        updateAgent,
        removeAgent,
        getAgentsByOrganization,
      }}
    >
      {children}
    </AgentContext.Provider>
  )
}

export function useAgent() {
  const context = useContext(AgentContext)
  if (context === undefined) {
    throw new Error("useAgent must be used within an AgentProvider")
  }
  return context
}
