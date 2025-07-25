"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"

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
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [currentOrganization, setCurrentOrganization] = useState<Organization | null>(null)

  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(false)

  // Fetch data from backend
  const fetchData = async () => {
    try {
      setLoading(true)
      const backendUrl = 'http://localhost:8080'
      
      // Fetch organizations
      const orgsResponse = await fetch(`${backendUrl}/api/frontend/organizations`)
      if (orgsResponse.ok) {
        const orgsData = await orgsResponse.json()
        setOrganizations(orgsData.organizations || [])
        if (orgsData.organizations && orgsData.organizations.length > 0 && !currentOrganization) {
          setCurrentOrganization(orgsData.organizations[0])
        }
      }

      // Fetch agents  
      const agentsResponse = await fetch(`${backendUrl}/api/frontend/agents`)
      if (agentsResponse.ok) {
        const agentsData = await agentsResponse.json()
        setAgents(agentsData.agents || [])
      }
      
    } catch (error) {
      console.error('Failed to fetch data from backend:', error)
      
      // No fallback data - everything must come from backend
      // This ensures the UI only shows real data
      setOrganizations([])
      setAgents([])
      setCurrentOrganization(null)
    } finally {
      setLoading(false)
    }
  }

  // Load data on component mount
  useEffect(() => {
    fetchData()
  }, [])

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
