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
  const [lastFetchTime, setLastFetchTime] = useState<number>(0)

  // Cache duration: 5 minutes
  const CACHE_DURATION = 5 * 60 * 1000

  // Optimized fetch function with caching
  const fetchData = async (force = false) => {
    const now = Date.now()
    
    // Skip if recently fetched (unless forced)
    if (!force && now - lastFetchTime < CACHE_DURATION) {
      return
    }

    try {
      setLoading(true)
      const backendUrl = 'http://localhost:8080'
      
      // Use Promise.allSettled for better error handling
      const [orgsResult, agentsResult] = await Promise.allSettled([
        fetch(`${backendUrl}/api/frontend/organizations`, {
          signal: AbortSignal.timeout(8000) // 8 second timeout
        }),
        fetch(`${backendUrl}/api/frontend/agents`, {
          signal: AbortSignal.timeout(8000)
        })
      ])

      // Process organizations
      if (orgsResult.status === 'fulfilled' && orgsResult.value.ok) {
        const orgsData = await orgsResult.value.json()
        setOrganizations(orgsData.organizations || [])
        
        // Set current organization if none selected
        if (orgsData.organizations && orgsData.organizations.length > 0 && !currentOrganization) {
          setCurrentOrganization(orgsData.organizations[0])
        }
      } else {
        console.warn('Failed to fetch organizations')
        setOrganizations([])
      }

      // Process agents
      if (agentsResult.status === 'fulfilled' && agentsResult.value.ok) {
        const agentsData = await agentsResult.value.json()
        setAgents(agentsData.agents || [])
      } else {
        console.warn('Failed to fetch agents')
        setAgents([])
      }
      
      setLastFetchTime(now)
      console.log('✅ Agent provider data refreshed')
    } catch (error) {
      console.error('Failed to fetch data from backend:', error)
      
      // Only clear data on first load failure
      if (organizations.length === 0 && agents.length === 0) {
        setOrganizations([])
        setAgents([])
        setCurrentOrganization(null)
      }
    } finally {
      setLoading(false)
    }
  }

  // Load data on component mount with debouncing
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      fetchData(true)
    }, 100) // Small delay to prevent multiple rapid calls

    return () => clearTimeout(timeoutId)
  }, [])

  // Auto-refresh every 5 minutes (much less aggressive)
  useEffect(() => {
    const interval = setInterval(() => {
      if (!loading) {
        fetchData(false)
      }
    }, 5 * 60 * 1000) // 5 minutes

    return () => clearInterval(interval)
  }, [loading, lastFetchTime])

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
