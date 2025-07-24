"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { useAgent } from "@/components/agent-provider"
import { Plus, Settings, Activity, Trash2 } from "lucide-react"
import { useRouter } from "next/navigation"
import { useState } from "react"

export function ConnectedAgents() {
  const { agents, removeAgent } = useAgent()
  const router = useRouter()
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-green-500"
      case "inactive":
        return "bg-gray-500"
      case "error":
        return "bg-red-500"
      default:
        return "bg-gray-500"
    }
  }

  const formatLastSync = (lastSync: string) => {
    const date = new Date(lastSync)
    const now = new Date()
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60))

    if (diffInMinutes < 60) {
      return `${diffInMinutes} minutes ago`
    } else if (diffInMinutes < 1440) {
      return `${Math.floor(diffInMinutes / 60)} hours ago`
    } else {
      return `${Math.floor(diffInMinutes / 1440)} days ago`
    }
  }

  const handleDeleteAgent = (agentId: string) => {
    if (deleteConfirm === agentId) {
      removeAgent(agentId)
      setDeleteConfirm(null)
    } else {
      setDeleteConfirm(agentId)
      // Auto-cancel after 3 seconds
      setTimeout(() => setDeleteConfirm(null), 3000)
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <div>
          <CardTitle>Connected Agents</CardTitle>
          <CardDescription>Manage your AI agents</CardDescription>
        </div>
        <Button size="sm" onClick={() => router.push("/setup")}>
          <Plus className="h-4 w-4 mr-2" />
          Add Agent
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {agents.map((agent) => (
          <div key={agent.id} className="flex items-center justify-between p-3 border rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <div className={`h-3 w-3 rounded-full ${getStatusColor(agent.status)}`} />
                {agent.status === "active" && (
                  <div
                    className={`absolute inset-0 h-3 w-3 rounded-full ${getStatusColor(agent.status)} animate-ping opacity-75`}
                  />
                )}
              </div>
              <div>
                <p className="font-medium">{agent.name}</p>
                <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                  <span>{agent.provider.toUpperCase()}</span>
                  <span>•</span>
                  <span>{agent.models.length} models</span>
                  <span>•</span>
                  <span>Last sync: {formatLastSync(agent.lastSync)}</span>
                </div>
                {deleteConfirm === agent.id && (
                  <p className="text-xs text-red-600 dark:text-red-400 mt-1">Click delete again to confirm removal</p>
                )}
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant={agent.status === "active" ? "default" : "secondary"}>{agent.status}</Badge>
              <Button variant="ghost" size="sm">
                <Settings className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleDeleteAgent(agent.id)}
                className={deleteConfirm === agent.id ? "text-red-600 dark:text-red-400" : ""}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          </div>
        ))}
        {agents.length === 0 && (
          <div className="text-center py-8 text-muted-foreground">
            <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No agents connected yet</p>
            <p className="text-sm">Add your first AI agent to start monitoring</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
