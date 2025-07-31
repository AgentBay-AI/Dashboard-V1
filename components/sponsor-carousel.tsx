"use client"

import { useEffect, useState } from "react"
import Image from "next/image"

const sponsors = [
  { name: "OpenAI", logo: "/placeholder.svg?height=40&width=120&text=OpenAI" },
  { name: "Anthropic", logo: "/placeholder.svg?height=40&width=120&text=Anthropic" },
  { name: "Google AI", logo: "/placeholder.svg?height=40&width=120&text=Google" },
  { name: "Microsoft", logo: "/placeholder.svg?height=40&width=120&text=Microsoft" },
  { name: "AWS", logo: "/placeholder.svg?height=40&width=120&text=AWS" },
  { name: "Hugging Face", logo: "/placeholder.svg?height=40&width=120&text=HuggingFace" },
]

export function SponsorCarousel() {
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIndex((prevIndex) => (prevIndex + 1) % sponsors.length)
    }, 3000)

    return () => clearInterval(timer)
  }, [])

  return (
    <section className="border-y bg-muted/30 py-12">
      <div className="container">
        <div className="text-center mb-8">
          <p className="text-sm font-medium text-muted-foreground uppercase tracking-wide">Trusted by teams using</p>
        </div>

        <div className="relative overflow-hidden">
          <div className="flex items-center justify-center space-x-12 md:space-x-16">
            {sponsors.map((sponsor, index) => (
              <div
                key={sponsor.name}
                className={`flex-shrink-0 transition-all duration-500 ${
                  index === currentIndex ? "opacity-100 scale-110" : "opacity-60 scale-100"
                }`}
              >
                <Image
                  src={sponsor.logo || "/placeholder.svg"}
                  alt={sponsor.name}
                  width={120}
                  height={40}
                  className="h-8 w-auto object-contain filter grayscale hover:grayscale-0 transition-all duration-300"
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
