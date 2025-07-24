"use client"

import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, Play, Activity, BarChart3, Shield, DollarSign, Zap, AlertTriangle } from "lucide-react"

export function LandingHero() {
  const router = useRouter()

  return (
    <section className="w-full py-12 md:py-24 lg:py-32 xl:py-48 bg-white dark:bg-background">
      <div className="container px-4 md:px-6">
        <div className="grid gap-6 lg:grid-cols-[1fr_600px] lg:gap-12 xl:grid-cols-[1fr_700px]">
          <div className="flex flex-col justify-center space-y-4">
            <div className="space-y-2">
              <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl lg:text-6xl/none">
                The HR Department for Your AI Agents
              </h1>
              <p className="max-w-[600px] text-muted-foreground md:text-xl">
                Connect to any AI deployed anywhere. Monitor performance, security, and costs. Get notified about
                potential risks before they become problems.
              </p>
            </div>
            <div className="flex flex-col gap-2 min-[400px]:flex-row">
              <Button size="lg" className="group" onClick={() => router.push("/login")}>
                Get Started
                <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
              </Button>
              <Button size="lg" variant="outline" className="group bg-transparent">
                <Play className="mr-2 h-4 w-4" />
                View Demo
              </Button>
            </div>
          </div>

          {/* Dashboard Example */}
          <div className="hidden lg:block">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-primary/20 to-primary/40 rounded-lg blur-3xl opacity-50"></div>
              <Card className="relative bg-background/95 backdrop-blur-sm border shadow-2xl overflow-hidden">
                {/* Dashboard Header */}
                <div className="border-b bg-background/50 p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="h-6 w-6 rounded bg-primary/20"></div>
                      <span className="font-semibold text-sm">Nexus Dashboard</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 rounded-full bg-green-500"></div>
                      <span className="text-xs text-muted-foreground">Live</span>
                    </div>
                  </div>
                </div>

                <CardContent className="p-6">
                  {/* Stats Cards */}
                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="bg-background/80 rounded-lg p-3 border">
                      <div className="flex items-center gap-2 mb-1">
                        <Activity className="h-4 w-4 text-green-500" />
                        <span className="text-xs font-medium">Active Agents</span>
                      </div>
                      <div className="text-2xl font-bold">3</div>
                      <div className="text-xs text-green-500">+2 this week</div>
                    </div>
                    <div className="bg-background/80 rounded-lg p-3 border">
                      <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                        <span className="text-xs font-medium">Alerts</span>
                      </div>
                      <div className="text-2xl font-bold">1</div>
                      <div className="text-xs text-amber-500">Security</div>
                    </div>
                  </div>

                  {/* Performance Chart */}
                  <div className="bg-background/80 rounded-lg p-4 border mb-4">
                    <div className="flex items-center gap-2 mb-3">
                      <BarChart3 className="h-4 w-4 text-primary" />
                      <span className="text-sm font-medium">Performance</span>
                      <Badge variant="outline" className="ml-auto text-xs">
                        95%
                      </Badge>
                    </div>
                    <div className="h-20 flex items-end gap-1">
                      {[65, 78, 72, 85, 68, 90, 95, 88, 92, 87, 94, 96].map((height, i) => (
                        <div key={i} className="bg-primary/60 rounded-t flex-1" style={{ height: `${height}%` }}></div>
                      ))}
                    </div>
                  </div>

                  {/* Connected Agents */}
                  <div className="bg-background/80 rounded-lg p-4 border">
                    <div className="flex items-center gap-2 mb-3">
                      <Zap className="h-4 w-4 text-primary" />
                      <span className="text-sm font-medium">Connected Agents</span>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between p-2 bg-background/50 rounded">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-2 rounded-full bg-green-500"></div>
                          <span className="text-xs">OpenAI GPT-4</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          Active
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-background/50 rounded">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-2 rounded-full bg-green-500"></div>
                          <span className="text-xs">Claude 3 Opus</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          Active
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-background/50 rounded">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-2 rounded-full bg-amber-500"></div>
                          <span className="text-xs">Custom Model</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          Warning
                        </Badge>
                      </div>
                    </div>
                  </div>

                  {/* Bottom Stats */}
                  <div className="grid grid-cols-3 gap-2 mt-4">
                    <div className="text-center p-2 bg-background/50 rounded">
                      <Shield className="h-4 w-4 mx-auto mb-1 text-green-500" />
                      <div className="text-xs font-medium">98%</div>
                      <div className="text-xs text-muted-foreground">Security</div>
                    </div>
                    <div className="text-center p-2 bg-background/50 rounded">
                      <DollarSign className="h-4 w-4 mx-auto mb-1 text-primary" />
                      <div className="text-xs font-medium">$1,250</div>
                      <div className="text-xs text-muted-foreground">Monthly</div>
                    </div>
                    <div className="text-center p-2 bg-background/50 rounded">
                      <Activity className="h-4 w-4 mx-auto mb-1 text-blue-500" />
                      <div className="text-xs font-medium">12.4K</div>
                      <div className="text-xs text-muted-foreground">Requests</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
