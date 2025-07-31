import { LandingHeader } from "@/components/landing-header"
import { LandingHero } from "@/components/landing/landing-hero"
import { SponsorCarousel } from "@/components/sponsor-carousel"
import { ProductTour } from "@/components/product-tour"
import { FeaturesGrid } from "@/components/features-grid"
import { LandingFooter } from "@/components/landing-footer"

export default function Home() {
  return (
    <div className="min-h-screen">
      <LandingHeader />
      <main>
        <LandingHero />
        <SponsorCarousel />
        <ProductTour />
        <FeaturesGrid />
      </main>
      <LandingFooter />
    </div>
  )
}
