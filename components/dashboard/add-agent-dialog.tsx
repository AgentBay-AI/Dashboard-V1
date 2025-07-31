"use client"

import type React from "react"

import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { useAgent } from "@/components/agent-provider"
import { Loader2 } from "lucide-react"

interface AddAgentDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AddAgentDialog({ open, onOpenChange }: AddAgentDialogProps) {
  const { addAgent } = useAgent()
  const [isLoading, setIsLoading] = useState(false)
  const [formData, setFormData] = useState({
    name: "",
    provider: "",
    apiKey: "",
    models: [] as string[],
  })

  const providerModels = {
    openai: ["gpt-4o", "gpt-3.5-turbo", "dall-e-3", "whisper"],
    anthropic: ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
    custom: ["custom-model-1", "custom-model-2"],
  }

  const handleModelToggle = (model: string) => {
    setFormData((prev) => ({
      ...prev,
      models: prev.models.includes(model) ? prev.models.filter((m) => m !== model) : [...prev.models, model],
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1500))

    const newAgent = {
      id: Date.now().toString(),
      name: formData.name || `${formData.provider.toUpperCase()} Agent`,
      provider: formData.provider,
      status: "active" as const,
      lastSync: new Date().toISOString(),
      models: formData.models,
      apiKey: formData.apiKey,
      performance: Math.floor(Math.random() * 20) + 80, // 80-100
      cost: Math.floor(Math.random() * 500) + 100, // 100-600
      requests: Math.floor(Math.random() * 10000) + 1000, // 1000-11000
    }

    addAgent(newAgent)
    setIsLoading(false)
    onOpenChange(false)

    // Reset form
    setFormData({
      name: "",
      provider: "",
      apiKey: "",
      models: [],
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Add New Agent</DialogTitle>
          <DialogDescription>
            Connect a new AI agent to start monitoring its performance and behavior.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="agent-name">Agent Name</Label>
              <Input
                id="agent-name"
                placeholder="My AI Agent"
                value={formData.name}
                onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="provider">Provider</Label>
              <Select
                value={formData.provider}
                onValueChange={(value) => setFormData((prev) => ({ ...prev, provider: value, models: [] }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a provider" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="openai">OpenAI</SelectItem>
                  <SelectItem value="anthropic">Anthropic</SelectItem>
                  <SelectItem value="custom">Custom API</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="api-key">API Key</Label>
              <Input
                id="api-key"
                type="password"
                placeholder="Enter your API key"
                value={formData.apiKey}
                onChange={(e) => setFormData((prev) => ({ ...prev, apiKey: e.target.value }))}
                required
              />
            </div>
            {formData.provider && (
              <div className="grid gap-2">
                <Label>Models to Monitor</Label>
                <div className="grid grid-cols-2 gap-2">
                  {providerModels[formData.provider as keyof typeof providerModels]?.map((model) => (
                    <div key={model} className="flex items-center space-x-2">
                      <Checkbox
                        id={model}
                        checked={formData.models.includes(model)}
                        onCheckedChange={() => handleModelToggle(model)}
                      />
                      <label
                        htmlFor={model}
                        className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                      >
                        {model}
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isLoading || !formData.provider || !formData.apiKey}>
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Adding...
                </>
              ) : (
                "Add Agent"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
