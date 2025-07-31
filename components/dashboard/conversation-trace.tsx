import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft } from "lucide-react"
import { Button } from "@/components/ui/button"

export function ConversationTrace() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
              <span className="sr-only">Back</span>
            </Button>
            <CardTitle className="text-base font-medium">Trace ID: 7824a8fed9e9e7aa4f02dbbd426a40a</CardTitle>
          </div>
          <CardDescription>Conversation between user and AI assistant</CardDescription>
        </div>
        <Badge>4 messages</Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-4">
          <div className="rounded-lg bg-muted p-4">
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline">System</Badge>
              <span className="text-xs text-muted-foreground">Message 0</span>
            </div>
            <p className="text-sm">
              You are a helpful AI assistant. <br />
              Solve tasks using your coding and language skills. <br />
              In the following cases, suggest Python code (in a python coding block).
            </p>
          </div>

          <div className="rounded-lg bg-muted p-4">
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline">User</Badge>
              <span className="text-xs text-muted-foreground">Message 1</span>
            </div>
            <p className="text-sm">Hello, can you help me solve a math problem? What is 2+2?</p>
          </div>

          <div className="rounded-lg bg-accent/50 p-4">
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline">Assistant</Badge>
              <span className="text-xs text-muted-foreground">Message 2</span>
            </div>
            <p className="text-sm">Sure, you can solve this math problem with a simple Python script:</p>
            <div className="mt-2 rounded-md bg-muted p-3">
              <pre className="text-sm">
                <code>python print(2 + 2) # Output: 4</code>
              </pre>
            </div>
            <p className="mt-2 text-sm">Please run this code. Once executed, this will print 4.</p>
          </div>

          <div className="rounded-lg bg-muted p-4">
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline">User</Badge>
              <span className="text-xs text-muted-foreground">Message 3</span>
            </div>
            <p className="text-sm">Hey</p>
          </div>
        </div>

        <div className="space-y-2">
          <h3 className="text-sm font-medium">Conversation Analysis</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-md border p-3">
              <div className="text-xs font-medium text-muted-foreground">Response Time</div>
              <div className="text-lg font-bold">245ms</div>
            </div>
            <div className="rounded-md border p-3">
              <div className="text-xs font-medium text-muted-foreground">Token Usage</div>
              <div className="text-lg font-bold">128 tokens</div>
            </div>
            <div className="rounded-md border p-3">
              <div className="text-xs font-medium text-muted-foreground">Model</div>
              <div className="text-lg font-bold">GPT-4o</div>
            </div>
            <div className="rounded-md border p-3">
              <div className="text-xs font-medium text-muted-foreground">Cost</div>
              <div className="text-lg font-bold">$0.008</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
