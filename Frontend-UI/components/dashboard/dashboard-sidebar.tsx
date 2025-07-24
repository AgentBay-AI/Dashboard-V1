"use client"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { usePathname, useRouter } from "next/navigation"
import Link from "next/link"
import {
  LayoutDashboard,
  BarChart3,
  DollarSign,
  MessageSquare,
  Shield,
  Settings,
  Monitor,
  Plus,
  Building2,
} from "lucide-react"

const sidebarNavItems = [
  {
    title: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    title: "Analysis",
    href: "/dashboard/analysis",
    icon: BarChart3,
  },
  {
    title: "Frontend Analytics",
    href: "/dashboard/frontend",
    icon: Monitor,
  },
  {
    title: "Cost Tracking",
    href: "/dashboard/cost",
    icon: DollarSign,
  },
  {
    title: "Conversations",
    href: "/dashboard/conversations",
    icon: MessageSquare,
  },
  {
    title: "Security & Compliance",
    href: "/dashboard/security",
    icon: Shield,
  },
  {
    title: "Settings",
    href: "/dashboard/settings",
    icon: Settings,
  },
]

export function DashboardSidebar() {
  const pathname = usePathname()
  const router = useRouter()

  return (
    <div className="flex h-full w-64 flex-col border-r border-border/40 bg-background">
      <div className="p-4 border-b border-border/40">
        <div className="space-y-2">
          <Button className="w-full justify-start gap-2 h-9" onClick={() => router.push("/setup?type=agent")}>
            <Plus className="h-4 w-4" />
            <span>Add Agent</span>
          </Button>
          <Button
            variant="outline"
            className="w-full justify-start gap-2 h-9 bg-transparent"
            onClick={() => router.push("/setup?type=organization")}
          >
            <Building2 className="h-4 w-4" />
            <span>New Organization</span>
          </Button>
        </div>
      </div>

      <ScrollArea className="flex-1 px-3 py-4">
        <div className="space-y-1">
          {sidebarNavItems.map((item) => (
            <Button
              key={item.href}
              variant={pathname === item.href ? "secondary" : "ghost"}
              className={cn(
                "w-full justify-start gap-3 h-9 font-normal",
                pathname === item.href && "bg-secondary font-medium",
              )}
              asChild
            >
              <Link href={item.href}>
                <item.icon className="h-4 w-4" />
                {item.title}
              </Link>
            </Button>
          ))}
        </div>
      </ScrollArea>
    </div>
  )
}
