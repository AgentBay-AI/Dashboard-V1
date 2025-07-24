"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ThemeToggle } from "@/components/theme-toggle"
import { Bell, Search, Settings, User, LogOut, Menu } from "lucide-react"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { DashboardSidebar } from "./dashboard-sidebar"

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

      {/* Glowing Background Square */}
      <rect x="8" y="8" width="24" height="24" rx="4" fill="url(#glowGradient)" filter="url(#glow)" opacity="0.6">
        <animate attributeName="opacity" values="0.4;0.8;0.4" dur="3s" repeatCount="indefinite" />
      </rect>

      {/* Inner Square Border */}
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

      {/* Letter N */}
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

export function DashboardHeader() {
  const pathname = usePathname()
  const [isSearchOpen, setIsSearchOpen] = useState(false)

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between px-4">
        <div className="flex items-center gap-3">
          <Sheet>
            <SheetTrigger asChild>
              <Button variant="ghost" size="sm" className="md:hidden h-8 w-8 p-0">
                <Menu className="h-4 w-4" />
                <span className="sr-only">Toggle menu</span>
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="p-0 w-64">
              <DashboardSidebar />
            </SheetContent>
          </Sheet>
          <Link href="/dashboard" className="flex items-center space-x-2">
            <NexusLogo className="h-10 w-10" />
            <span className="hidden font-semibold text-foreground sm:inline-block">Nexus</span>
          </Link>
        </div>

        <div className="flex items-center gap-2">
          {isSearchOpen ? (
            <div className="relative w-full max-w-sm">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                type="search"
                placeholder="Search..."
                className="w-full pl-8 h-8"
                autoFocus
                onBlur={() => setIsSearchOpen(false)}
              />
            </div>
          ) : (
            <Button variant="ghost" size="sm" onClick={() => setIsSearchOpen(true)} className="h-8 w-8 p-0">
              <Search className="h-4 w-4" />
              <span className="sr-only">Search</span>
            </Button>
          )}

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="relative h-8 w-8 p-0">
                <Bell className="h-4 w-4" />
                <span className="sr-only">Notifications</span>
                <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-red-500"></span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel>Notifications</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <div className="max-h-80 overflow-auto">
                <DropdownMenuItem className="flex flex-col items-start p-3 cursor-pointer">
                  <div className="flex items-center gap-2 mb-1 w-full">
                    <span className="h-2 w-2 rounded-full bg-red-500"></span>
                    <span className="font-medium text-sm">Security Alert</span>
                    <span className="text-xs text-muted-foreground ml-auto">2h ago</span>
                  </div>
                  <p className="text-sm text-muted-foreground">New security alert detected</p>
                </DropdownMenuItem>
                <DropdownMenuItem className="flex flex-col items-start p-3 cursor-pointer">
                  <div className="flex items-center gap-2 mb-1 w-full">
                    <span className="h-2 w-2 rounded-full bg-blue-500"></span>
                    <span className="font-medium text-sm">API Connection</span>
                    <span className="text-xs text-muted-foreground ml-auto">5h ago</span>
                  </div>
                  <p className="text-sm text-muted-foreground">API connection successful</p>
                </DropdownMenuItem>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="justify-center">
                <Link href="/dashboard/notifications" className="w-full text-center text-sm">
                  View all notifications
                </Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <ThemeToggle />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="rounded-full h-8 w-8 p-0">
                <User className="h-4 w-4" />
                <span className="sr-only">User menu</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>My Account</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <User className="mr-2 h-4 w-4" />
                <span>Profile</span>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Settings className="mr-2 h-4 w-4" />
                <span>Settings</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <LogOut className="mr-2 h-4 w-4" />
                <span>Log out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
