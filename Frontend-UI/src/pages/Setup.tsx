import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { 
  ArrowRight, 
  Building2, 
  Bot, 
  Code, 
  Smartphone, 
  Key, 
  AlertTriangle,
  Copy,
  CheckCircle
} from "lucide-react";

type SetupStep = "login" | "choice" | "organization" | "agent-type" | "agent-details" | "llm-provider" | "sdk-setup" | "platform-choice" | "complete";

const Setup = () => {
  const [currentStep, setCurrentStep] = useState<SetupStep>("login");
  const [setupData, setSetupData] = useState({
    email: "",
    password: "",
    choice: "",
    orgName: "",
    orgType: "",
    orgDescription: "",
    agentType: "",
    agentName: "",
    agentDescription: "",
    agentUseCase: "",
    llmProviders: [] as string[],
    platform: "",
    apiKey: ""
  });

  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKeyCopied, setApiKeyCopied] = useState(false);

  const generateApiKey = () => {
    const key = `sk-${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
    setSetupData(prev => ({ ...prev, apiKey: key }));
    setShowApiKey(true);
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(setupData.apiKey);
    setApiKeyCopied(true);
    setTimeout(() => setApiKeyCopied(false), 2000);
  };

  const handleNext = () => {
    const stepFlow: Record<SetupStep, SetupStep> = {
      "login": "choice",
      "choice": setupData.choice === "organization" ? "organization" : "agent-type",
      "organization": "agent-type",
      "agent-type": setupData.agentType === "coded" ? "agent-details" : "platform-choice",
      "agent-details": "llm-provider",
      "llm-provider": "sdk-setup",
      "platform-choice": "complete",
      "sdk-setup": "complete",
      "complete": "complete"
    };

    setCurrentStep(stepFlow[currentStep]);
  };

  const platforms = [
    "Dialogflow",
    "Microsoft Bot Framework", 
    "Amazon Lex",
    "Rasa",
    "Botpress",
    "Voiceflow"
  ];

  const renderStep = () => {
    switch (currentStep) {
      case "login":
        return (
          <Card className="w-full max-w-md mx-auto animate-fade-in">
            <CardHeader className="text-center">
              <CardTitle className="text-2xl">Welcome</CardTitle>
              <CardDescription>Sign in to access your analytics dashboard</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="enter@example.com"
                  value={setupData.email}
                  onChange={(e) => setSetupData(prev => ({ ...prev, email: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={setupData.password}
                  onChange={(e) => setSetupData(prev => ({ ...prev, password: e.target.value }))}
                />
              </div>
              <Button 
                onClick={handleNext} 
                className="w-full"
                disabled={!setupData.email || !setupData.password}
              >
                Sign In
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "choice":
        return (
          <Card className="w-full max-w-md mx-auto animate-fade-in">
            <CardHeader className="text-center">
              <CardTitle>What would you like to create?</CardTitle>
              <CardDescription>Choose your setup type</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                variant={setupData.choice === "organization" ? "default" : "outline"}
                className="w-full h-20 flex flex-col space-y-2"
                onClick={() => setSetupData(prev => ({ ...prev, choice: "organization" }))}
              >
                <Building2 className="h-8 w-8" />
                <span>Create Organization</span>
              </Button>
              <Button
                variant={setupData.choice === "agent" ? "default" : "outline"}
                className="w-full h-20 flex flex-col space-y-2"
                onClick={() => setSetupData(prev => ({ ...prev, choice: "agent" }))}
              >
                <Bot className="h-8 w-8" />
                <span>Add Agent</span>
              </Button>
              <Button 
                onClick={handleNext} 
                className="w-full mt-6"
                disabled={!setupData.choice}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "organization":
        return (
          <Card className="w-full max-w-lg mx-auto animate-fade-in">
            <CardHeader>
              <CardTitle>Create Organization</CardTitle>
              <CardDescription>Set up your organization details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="orgName">Organization Name</Label>
                <Input
                  id="orgName"
                  placeholder="Acme Corp"
                  value={setupData.orgName}
                  onChange={(e) => setSetupData(prev => ({ ...prev, orgName: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="orgType">Organization Type</Label>
                <Select value={setupData.orgType} onValueChange={(value) => setSetupData(prev => ({ ...prev, orgType: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="startup">Startup</SelectItem>
                    <SelectItem value="enterprise">Enterprise</SelectItem>
                    <SelectItem value="agency">Agency</SelectItem>
                    <SelectItem value="nonprofit">Non-profit</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="orgDescription">Description</Label>
                <Textarea
                  id="orgDescription"
                  placeholder="Describe your organization..."
                  value={setupData.orgDescription}
                  onChange={(e) => setSetupData(prev => ({ ...prev, orgDescription: e.target.value }))}
                />
              </div>
              <Button 
                onClick={handleNext} 
                className="w-full"
                disabled={!setupData.orgName || !setupData.orgType}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "agent-type":
        return (
          <Card className="w-full max-w-md mx-auto animate-fade-in">
            <CardHeader className="text-center">
              <CardTitle>Agent Type</CardTitle>
              <CardDescription>How is your agent built?</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                variant={setupData.agentType === "coded" ? "default" : "outline"}
                className="w-full h-20 flex flex-col space-y-2"
                onClick={() => setSetupData(prev => ({ ...prev, agentType: "coded" }))}
              >
                <Code className="h-8 w-8" />
                <span>Coded Platform</span>
                <small className="text-xs opacity-70">Custom built with APIs</small>
              </Button>
              <Button
                variant={setupData.agentType === "no-code" ? "default" : "outline"}
                className="w-full h-20 flex flex-col space-y-2"
                onClick={() => setSetupData(prev => ({ ...prev, agentType: "no-code" }))}
              >
                <Smartphone className="h-8 w-8" />
                <span>No-Code Platform</span>
                <small className="text-xs opacity-70">Built with visual tools</small>
              </Button>
              <Button 
                onClick={handleNext} 
                className="w-full mt-6"
                disabled={!setupData.agentType}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "agent-details":
        return (
          <Card className="w-full max-w-lg mx-auto animate-fade-in">
            <CardHeader>
              <CardTitle>Agent Details</CardTitle>
              <CardDescription>Tell us about your coded agent</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="agentName">Agent Name</Label>
                <Input
                  id="agentName"
                  placeholder="My AI Assistant"
                  value={setupData.agentName}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentName: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="agentDescription">Description</Label>
                <Textarea
                  id="agentDescription"
                  placeholder="Describe what your agent does..."
                  value={setupData.agentDescription}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentDescription: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="agentUseCase">Primary Use Case</Label>
                <Input
                  id="agentUseCase"
                  placeholder="Customer support, sales, etc."
                  value={setupData.agentUseCase}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentUseCase: e.target.value }))}
                />
              </div>
              <Button 
                onClick={handleNext} 
                className="w-full"
                disabled={!setupData.agentName || !setupData.agentDescription}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "llm-provider":
        const handleProviderToggle = (provider: string, checked: boolean) => {
          setSetupData(prev => ({
            ...prev,
            llmProviders: checked 
              ? [...prev.llmProviders, provider]
              : prev.llmProviders.filter(p => p !== provider)
          }));
        };

        return (
          <Card className="w-full max-w-md mx-auto animate-fade-in">
            <CardHeader className="text-center">
              <CardTitle>LLM Providers</CardTitle>
              <CardDescription>Select the AI providers you're using (multiple selection allowed)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {["OpenAI", "Anthropic", "Gemini"].map((provider) => (
                <div key={provider} className="flex items-center space-x-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                  <Checkbox
                    id={provider}
                    checked={setupData.llmProviders.includes(provider)}
                    onCheckedChange={(checked) => handleProviderToggle(provider, checked as boolean)}
                  />
                  <Label htmlFor={provider} className="flex-1 cursor-pointer font-medium">
                    {provider}
                  </Label>
                </div>
              ))}
              
              {setupData.llmProviders.length > 0 && (
                <div className="mt-4 p-3 bg-muted/50 rounded-lg">
                  <p className="text-sm font-medium mb-2">Selected providers:</p>
                  <div className="flex flex-wrap gap-2">
                    {setupData.llmProviders.map(provider => (
                      <Badge key={provider} variant="secondary">{provider}</Badge>
                    ))}
                  </div>
                </div>
              )}
              
              <Button 
                onClick={handleNext} 
                className="w-full mt-6"
                disabled={setupData.llmProviders.length === 0}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "platform-choice":
        return (
          <Card className="w-full max-w-lg mx-auto animate-fade-in">
            <CardHeader>
              <CardTitle>Platform Selection</CardTitle>
              <CardDescription>Which no-code platform are you using?</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {platforms.map((platform) => (
                  <Button
                    key={platform}
                    variant={setupData.platform === platform ? "default" : "outline"}
                    className="h-16 flex flex-col"
                    onClick={() => setSetupData(prev => ({ ...prev, platform }))}
                  >
                    <span className="text-sm">{platform}</span>
                  </Button>
                ))}
              </div>
              <Button 
                onClick={() => {
                  generateApiKey();
                  handleNext();
                }}
                className="w-full mt-6"
                disabled={!setupData.platform}
              >
                Generate API Key
                <Key className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "sdk-setup":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader>
              <CardTitle>SDK Integration</CardTitle>
              <CardDescription>Follow these steps to integrate our analytics SDK</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <Badge className="mt-1">1</Badge>
                  <div>
                    <h4 className="font-medium">Install the SDK</h4>
                    <div className="mt-2 p-3 bg-muted rounded-lg font-mono text-sm">
                      npm install @analytics-dashboard/sdk
                    </div>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Badge className="mt-1">2</Badge>
                  <div>
                    <h4 className="font-medium">Initialize in your code</h4>
                    <div className="mt-2 p-3 bg-muted rounded-lg font-mono text-sm">
                       {`import { AnalyticsSDK } from '@analytics-dashboard/sdk';

const analytics = new AnalyticsSDK({
  apiKey: 'YOUR_API_KEY',
  providers: [${setupData.llmProviders.map(p => `'${p}'`).join(', ')}]
});`}
                    </div>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Badge className="mt-1">3</Badge>
                  <div className="w-full">
                    <h4 className="font-medium">Your API Key</h4>
                    <Alert className="mt-2">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        <strong>Important:</strong> Store this in your .env file as BACKEND_API_KEY. 
                        This key will not be available after 1 hour for security reasons.
                      </AlertDescription>
                    </Alert>
                    <div className="mt-3 flex items-center space-x-2">
                      <Input 
                        value={setupData.apiKey} 
                        readOnly 
                        className="font-mono"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={copyApiKey}
                      >
                        {apiKeyCopied ? <CheckCircle className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <Button 
                onClick={handleNext}
                className="w-full"
              >
                Continue to Dashboard
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      case "complete":
        if (!setupData.apiKey) {
          generateApiKey();
        }
        
        return (
          <Card className="w-full max-w-lg mx-auto animate-fade-in">
            <CardHeader className="text-center">
              <CardTitle className="flex items-center justify-center space-x-2">
                <CheckCircle className="h-6 w-6 text-success" />
                <span>Setup Complete!</span>
              </CardTitle>
              <CardDescription>
                Your agent is ready and your API key has been generated.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium mb-2">Your API Key</h4>
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Important:</strong> Store this in your .env file as BACKEND_API_KEY. 
                      This key will not be available after 1 hour for security reasons.
                    </AlertDescription>
                  </Alert>
                  <div className="mt-3 flex items-center space-x-2">
                    <Input 
                      value={setupData.apiKey} 
                      readOnly 
                      className="font-mono"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={copyApiKey}
                    >
                      {apiKeyCopied ? <CheckCircle className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              </div>
              
              <div className="text-center space-y-2">
                <p className="text-sm text-muted-foreground">
                  {setupData.agentType === "coded" ? "SDK integration ready" : "Platform connected successfully"}
                </p>
              </div>
              
              <Button 
                onClick={() => window.location.href = "/dashboard"}
                className="w-full"
              >
                Access Dashboard
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        );

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-4xl">
        {/* Progress Indicator */}
        <div className="mb-8">
          <div className="flex justify-center space-x-2 mb-4">
            {Array.from({ length: 5 }, (_, i) => (
              <div
                key={i}
                className={`w-2 h-2 rounded-full transition-colors ${
                  i < Object.values(setupData).filter(Boolean).length 
                    ? 'bg-primary' 
                    : 'bg-muted'
                }`}
              />
            ))}
          </div>
        </div>

        {renderStep()}
      </div>
    </div>
  );
};

export default Setup;