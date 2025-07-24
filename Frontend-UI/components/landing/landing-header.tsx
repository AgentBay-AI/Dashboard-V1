"use client"

import { useState } from "react"
import Link from "next/link"
import Image from "next/image"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Menu, Github, Twitter } from "lucide-react"
import { ThemeToggle } from "@/components/theme-toggle"

export function LandingHeader() {
  const [isOpen, setIsOpen] = useState(false)
  const router = useRouter()

  const navItems = [
    { label: "Home", href: "/" },
    { label: "Blog", href: "/blog" },
    { label: "Docs", href: "/docs" },
    { label: "Pricing", href: "/pricing" },
    { label: "Contact", href: "/contact" },
  ]

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <div className="flex items-center gap-6 md:gap-10">
          <Link href="/" className="flex items-center space-x-2">
            <Image src="/logo.png" alt="Nexus Logo" width={32} height={32} />
            <span className="hidden font-bold sm:inline-block">Nexus</span>
          </Link>
          <nav className="hidden gap-6 md:flex">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="text-sm font-medium transition-colors hover:text-primary"
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          <div className="hidden md:flex items-center gap-2">
            <Link href="https://github.com" target="_blank" rel="noreferrer">
              <Button variant="ghost" size="icon">
                <Github className="h-4 w-4" />
                <span className="sr-only">GitHub</span>
              </Button>
            </Link>
            <Link href="https://twitter.com" target="_blank" rel="noreferrer">
              <Button variant="ghost" size="icon">
                <Twitter className="h-4 w-4" />
                <span className="sr-only">Twitter</span>
              </Button>
            </Link>
            <ThemeToggle />
          </div>
          <Button variant="default" className="hidden md:flex" onClick={() => router.push("/login")}>
            Dashboard
          </Button>
          <Sheet open={isOpen} onOpenChange={setIsOpen}>
            <SheetTrigger asChild>
              <Button variant="outline" size="icon" className="md:hidden bg-transparent">
                <Menu className="h-5 w-5" />
                <span className="sr-only">Toggle menu</span>
              </Button>
            </SheetTrigger>
            <SheetContent side="right">
              <div className="flex flex-col space-y-4 pt-6">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="text-sm font-medium transition-colors hover:text-primary"
                    onClick={() => setIsOpen(false)}
                  >
                    {item.label}
                  </Link>
                ))}
                <div className="flex items-center gap-2 pt-4">
                  <Link href="https://github.com" target="_blank" rel="noreferrer">
                    <Button variant="ghost" size="icon">
                      <Github className="h-4 w-4" />
                      <span className="sr-only">GitHub</span>
                    </Button>
                  </Link>
                  <Link href="https://twitter.com" target="_blank" rel="noreferrer">
                    <Button variant="ghost" size="icon">
                      <Twitter className="h-4 w-4" />
                      <span className="sr-only">Twitter</span>
                    </Button>
                  </Link>
                  <ThemeToggle />
                </div>
                <Button
                  variant="default"
                  className="mt-4"
                  onClick={() => {
                    setIsOpen(false)
                    router.push("/login")
                  }}
                >
                  Dashboard
                </Button>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  )
}
