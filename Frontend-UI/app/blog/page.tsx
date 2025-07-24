import { LandingHeader } from "@/components/landing-header"
import { LandingFooter } from "@/components/landing-footer"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { CalendarDays, Clock, User } from "lucide-react"

export default function BlogPage() {
  const posts = [
    {
      title: "The Future of AI Agent Monitoring",
      description: "Exploring the latest trends and technologies in AI agent monitoring and management.",
      author: "Sarah Chen",
      date: "2024-01-15",
      readTime: "5 min read",
      category: "Technology",
      featured: true,
    },
    {
      title: "Best Practices for AI Security",
      description: "Essential security measures every organization should implement for their AI agents.",
      author: "Michael Rodriguez",
      date: "2024-01-12",
      readTime: "8 min read",
      category: "Security",
    },
    {
      title: "Cost Optimization Strategies",
      description: "How to reduce AI operational costs without compromising performance.",
      author: "Emily Johnson",
      date: "2024-01-10",
      readTime: "6 min read",
      category: "Finance",
    },
    {
      title: "Understanding AI Agent Behavior",
      description: "Deep dive into analyzing and interpreting AI agent behavioral patterns.",
      author: "David Kim",
      date: "2024-01-08",
      readTime: "10 min read",
      category: "Analytics",
    },
    {
      title: "Compliance in AI Systems",
      description: "Navigating regulatory requirements and compliance standards for AI deployments.",
      author: "Lisa Wang",
      date: "2024-01-05",
      readTime: "7 min read",
      category: "Compliance",
    },
    {
      title: "Real-time Monitoring Techniques",
      description: "Advanced techniques for implementing real-time monitoring of AI agents.",
      author: "James Thompson",
      date: "2024-01-03",
      readTime: "9 min read",
      category: "Technology",
    },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-background/95">
      <LandingHeader />
      <main className="container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold tracking-tight mb-4">Nexus Blog</h1>
            <p className="text-xl text-muted-foreground">
              Insights, best practices, and the latest trends in AI agent monitoring
            </p>
          </div>

          <div className="grid gap-8">
            {posts.map((post, index) => (
              <Card
                key={index}
                className={`cursor-pointer hover:shadow-lg transition-shadow ${post.featured ? "border-primary" : ""}`}
              >
                {post.featured && (
                  <div className="bg-primary text-primary-foreground text-center py-1 text-sm font-medium">
                    Featured Post
                  </div>
                )}
                <CardHeader>
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="outline">{post.category}</Badge>
                    <div className="flex items-center text-sm text-muted-foreground gap-4">
                      <div className="flex items-center gap-1">
                        <CalendarDays className="h-4 w-4" />
                        {new Date(post.date).toLocaleDateString()}
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock className="h-4 w-4" />
                        {post.readTime}
                      </div>
                    </div>
                  </div>
                  <CardTitle className="text-2xl hover:text-primary transition-colors">{post.title}</CardTitle>
                  <CardDescription className="text-base">{post.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <User className="h-4 w-4" />
                    <span>By {post.author}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="text-center mt-12">
            <p className="text-muted-foreground">
              Want to stay updated? Subscribe to our newsletter for the latest insights.
            </p>
          </div>
        </div>
      </main>
      <LandingFooter />
    </div>
  )
}
