"use client"

import type React from "react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Mail, Lock, Github, Loader2 } from "lucide-react"

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

export default function LoginPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [loadingMethod, setLoadingMethod] = useState<string | null>(null)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setLoadingMethod("email")

    try {
      const formData = new FormData(e.target as HTMLFormElement)
      const email = formData.get("email") as string
      const password = formData.get("password") as string
      
      // Simple demo authentication - accepts any email/password
      setTimeout(() => {
        setIsLoading(false)
        setLoadingMethod(null)
        router.push("/dashboard")
      }, 1500)
    } catch (error) {
      console.error("Login failed:", error)
      setIsLoading(false)
      setLoadingMethod(null)
    }
  }

  const handleSocialLogin = async (provider: string) => {
    setIsLoading(true)
    setLoadingMethod(provider)

    try {
      // For demo, just redirect to dashboard after delay
      setTimeout(() => {
        setIsLoading(false)
        setLoadingMethod(null)
        router.push("/dashboard")
      }, 1500)
    } catch (error) {
      console.error("Social login failed:", error)
      setIsLoading(false)
      setLoadingMethod(null)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-1 text-center pb-6">
          <div className="flex justify-center mb-4">
            <NexusLogo className="h-12 w-12" />
          </div>
          <CardTitle className="text-2xl font-bold">Welcome to Nexus</CardTitle>
          <CardDescription>Access your AI agent dashboard</CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Social Sign In Options */}
          <div className="space-y-3">
            <Button
              variant="outline"
              className="w-full h-12 flex items-center justify-center gap-3 bg-transparent hover:bg-accent"
              onClick={() => handleSocialLogin("google")}
              disabled={isLoading}
            >
              {loadingMethod === "google" ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" height="20" viewBox="0 0 24 24" width="20" className="h-5 w-5">
                  <path
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    fill="#4285F4"
                  />
                  <path
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    fill="#34A853"
                  />
                  <path
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                    fill="#FBBC05"
                  />
                  <path
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                    fill="#EA4335"
                  />
                </svg>
              )}
              <span>{loadingMethod === "google" ? "Signing in..." : "Continue with Google"}</span>
            </Button>

            <Button
              variant="outline"
              className="w-full h-12 flex items-center justify-center gap-3 bg-transparent hover:bg-accent"
              onClick={() => handleSocialLogin("github")}
              disabled={isLoading}
            >
              {loadingMethod === "github" ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Github className="h-5 w-5" />
              )}
              <span>{loadingMethod === "github" ? "Signing in..." : "Continue with GitHub"}</span>
            </Button>
          </div>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <Separator className="w-full" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">Or continue with email</span>
            </div>
          </div>

          {/* Email Sign In Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input id="email" name="email" placeholder="name@example.com" type="email" className="pl-10 h-12" required />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <a href="#" className="text-sm text-primary hover:underline">
                  Forgot password?
                </a>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input id="password" name="password" type="password" className="pl-10 h-12" required />
              </div>
            </div>

            <Button type="submit" className="w-full h-12" disabled={isLoading}>
              {loadingMethod === "email" ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                "Access Dashboard"
              )}
            </Button>
          </form>
        </CardContent>

        <CardFooter className="flex flex-col space-y-4">
          <div className="text-center text-sm text-muted-foreground">
            Don&apos;t have an account?{" "}
            <a href="#" className="text-primary hover:underline">
              Sign up
            </a>
          </div>
        </CardFooter>
      </Card>
    </div>
  )
}
