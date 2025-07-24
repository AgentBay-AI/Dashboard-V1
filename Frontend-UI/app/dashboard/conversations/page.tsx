import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Search, Filter } from "lucide-react"
import { ConversationTrace } from "@/components/dashboard/conversation-trace"

export default function ConversationsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Conversations</h1>
        <p className="text-muted-foreground">Monitor and analyze conversations between users and your AI agents.</p>
      </div>

      <div className="flex items-center justify-between">
        <div className="relative w-full max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input type="search" placeholder="Search conversations..." className="w-full pl-8" />
        </div>
        <Button variant="outline" size="icon">
          <Filter className="h-4 w-4" />
          <span className="sr-only">Filter</span>
        </Button>
      </div>

      <Tabs defaultValue="recent">
        <TabsList>
          <TabsTrigger value="recent">Recent</TabsTrigger>
          <TabsTrigger value="flagged">Flagged</TabsTrigger>
          <TabsTrigger value="analyzed">Analyzed</TabsTrigger>
        </TabsList>
        <TabsContent value="recent" className="space-y-4 pt-4">
          <Card className="cursor-pointer hover:bg-accent/50">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base font-medium">Trace ID: 7824a8fed9e9e7aa4f02dbbd426a40a</CardTitle>
                <Badge>2 minutes ago</Badge>
              </div>
              <CardDescription>Math problem solving assistance</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between text-sm">
                <div>User requested help with a math problem</div>
                <Badge variant="outline">4 messages</Badge>
              </div>
            </CardContent>
          </Card>
          <Card className="cursor-pointer hover:bg-accent/50">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base font-medium">Trace ID: 6f12b3a9c8d7e6f5a4b3c2d1e0f9a8b7</CardTitle>
                <Badge>15 minutes ago</Badge>
              </div>
              <CardDescription>Code review assistance</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between text-sm">
                <div>User requested code review for JavaScript function</div>
                <Badge variant="outline">7 messages</Badge>
              </div>
            </CardContent>
          </Card>
          <Card className="cursor-pointer hover:bg-accent/50">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base font-medium">Trace ID: 5e4d3c2b1a0f9e8d7c6b5a4d3c2b1a0f</CardTitle>
                <Badge>1 hour ago</Badge>
              </div>
              <CardDescription>Product recommendation</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between text-sm">
                <div>User asked for product recommendations</div>
                <Badge variant="outline">12 messages</Badge>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="flagged" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle>Flagged Conversations</CardTitle>
              <CardDescription>
                Conversations that have been flagged for review based on content or behavior.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">No flagged conversations found.</p>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="analyzed" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle>Analyzed Conversations</CardTitle>
              <CardDescription>Conversations that have been analyzed for patterns and insights.</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">No analyzed conversations found.</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <ConversationTrace />
    </div>
  )
}
