"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Eye, EyeOff, Copy, RotateCcw } from "lucide-react"
import { useState } from "react"

export default function SettingsPage() {
  const [showApiKeys, setShowApiKeys] = useState<Record<string, boolean>>({})

  const apiKeys = [
    { provider: "OpenAI", key: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz", status: "active" },
    {
      provider: "Anthropic",
      key: "sk-ant-api03-xyz789abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567",
      status: "active",
    },
    { provider: "Gemini", key: "AIzaSyABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZ567", status: "inactive" },
    { provider: "Groq", key: "gsk_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc123def", status: "active" },
  ]

  const toggleKeyVisibility = (provider: string) => {
    setShowApiKeys((prev) => ({
      ...prev,
      [provider]: !prev[provider],
    }))
  }

  const maskApiKey = (key: string) => {
    if (key.length <= 8) return key
    return key.substring(0, 8) + "•".repeat(Math.min(32, key.length - 16)) + key.substring(key.length - 8)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-8 p-6">
      <div>
        <h1 className="text-3xl font-semibold text-slate-900 dark:text-slate-100">Settings</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Manage your account settings, API keys, and preferences
        </p>
      </div>

      <Tabs defaultValue="api-keys" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4 bg-slate-100 dark:bg-slate-800">
          <TabsTrigger value="api-keys">API Keys</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
        </TabsList>

        <TabsContent value="api-keys" className="space-y-6">
          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">
                API Keys Management
              </CardTitle>
              <CardDescription>
                Manage your API keys for different LLM providers. Keys are encrypted and stored securely.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {apiKeys.map((item) => (
                <div
                  key={item.provider}
                  className="flex items-center justify-between p-4 border border-slate-200 dark:border-slate-600 rounded-lg"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-medium text-slate-900 dark:text-slate-100">{item.provider}</h3>
                      <Badge variant={item.status === "active" ? "default" : "secondary"}>{item.status}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm font-mono bg-slate-100 dark:bg-slate-800 px-3 py-1 rounded border">
                        {showApiKeys[item.provider] ? item.key : maskApiKey(item.key)}
                      </code>
                      <Button variant="ghost" size="sm" onClick={() => toggleKeyVisibility(item.provider)}>
                        {showApiKeys[item.provider] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => copyToClipboard(item.key)}>
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm">
                      <RotateCcw className="h-4 w-4 mr-2" />
                      Regenerate
                    </Button>
                    <Button variant="outline" size="sm">
                      Edit
                    </Button>
                  </div>
                </div>
              ))}

              <div className="pt-4 border-t border-slate-200 dark:border-slate-600">
                <Button>Add New API Key</Button>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">Nexus API Access</CardTitle>
              <CardDescription>
                Access the Nexus API to integrate with your systems and automate workflows.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="nexus-token">API Token</Label>
                <div className="flex gap-2">
                  <Input
                    id="nexus-token"
                    readOnly
                    value="nxs_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567"
                    className="font-mono text-sm"
                  />
                  <Button variant="outline">Regenerate</Button>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="webhook-secret">Webhook Secret</Label>
                <div className="flex gap-2">
                  <Input
                    id="webhook-secret"
                    readOnly
                    value="whsec_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567"
                    className="font-mono text-sm"
                  />
                  <Button variant="outline">Regenerate</Button>
                </div>
              </div>
              <Button variant="secondary">View API Documentation</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6">
          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">
                Email Notifications
              </CardTitle>
              <CardDescription>Configure when you'll receive email notifications.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="security-alerts">Security Alerts</Label>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Receive notifications about security issues.
                  </p>
                </div>
                <Switch id="security-alerts" defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="performance-alerts">Performance Alerts</Label>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Receive notifications about performance issues.
                  </p>
                </div>
                <Switch id="performance-alerts" defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="cost-alerts">Cost Alerts</Label>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Receive notifications about cost thresholds.
                  </p>
                </div>
                <Switch id="cost-alerts" defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="weekly-reports">Weekly Reports</Label>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Receive weekly summary reports.</p>
                </div>
                <Switch id="weekly-reports" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">
                Notification Delivery
              </CardTitle>
              <CardDescription>Configure how you want to receive notifications.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="email">Email Address</Label>
                <Input id="email" defaultValue="alex@example.com" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="slack-webhook">Slack Webhook URL (Optional)</Label>
                <Input id="slack-webhook" placeholder="https://hooks.slack.com/services/..." />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="webhook-url">Custom Webhook URL (Optional)</Label>
                <Input id="webhook-url" placeholder="https://api.example.com/webhook" />
              </div>
              <Button>Save Notification Settings</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="account" className="space-y-6">
          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">
                Account Information
              </CardTitle>
              <CardDescription>Update your account details and preferences.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="name">Full Name</Label>
                <Input id="name" defaultValue="Alex Johnson" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="email-account">Email Address</Label>
                <Input id="email-account" defaultValue="alex@example.com" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="company">Company</Label>
                <Input id="company" defaultValue="Acme Inc." />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="timezone">Timezone</Label>
                <Select defaultValue="utc-8">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="utc-8">Pacific Time (UTC-8)</SelectItem>
                    <SelectItem value="utc-5">Eastern Time (UTC-5)</SelectItem>
                    <SelectItem value="utc+0">UTC</SelectItem>
                    <SelectItem value="utc+1">Central European Time (UTC+1)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button>Update Account</Button>
            </CardContent>
          </Card>

          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">Security</CardTitle>
              <CardDescription>Manage your account security settings.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input id="current-password" type="password" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input id="new-password" type="password" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input id="confirm-password" type="password" />
              </div>
              <Button>Change Password</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="preferences" className="space-y-6">
          <Card className="border-slate-200 dark:border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg font-medium text-slate-900 dark:text-slate-100">
                Dashboard Preferences
              </CardTitle>
              <CardDescription>Customize your dashboard layout and default views.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="default-view">Default Dashboard View</Label>
                <Select defaultValue="overview">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="overview">Overview</SelectItem>
                    <SelectItem value="performance">Performance</SelectItem>
                    <SelectItem value="security">Security</SelectItem>
                    <SelectItem value="cost">Cost Tracking</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="refresh-interval">Auto-refresh Interval</Label>
                <Select defaultValue="30">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10 seconds</SelectItem>
                    <SelectItem value="30">30 seconds</SelectItem>
                    <SelectItem value="60">1 minute</SelectItem>
                    <SelectItem value="300">5 minutes</SelectItem>
                    <SelectItem value="0">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="compact-view">Compact View</Label>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Show more information in less space.</p>
                </div>
                <Switch id="compact-view" />
              </div>

              <Button>Save Preferences</Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
