import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { 
  ArrowRight, 
  Bot, 
  Code, 
  Smartphone, 
  Key, 
  AlertTriangle,
  Copy,
  CheckCircle,
  Loader2
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { apiClient } from "@/lib/api";

type SetupStep = "agent-type" | "agent-details" | "llm-provider" | "sdk-setup" | "platform-choice" | "complete";

const AgentSetup = () => {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState<SetupStep>("agent-type");
  const [setupData, setSetupData] = useState({
    agentType: "",
    agentName: "",
    agentDescription: "",
    agentUseCase: "",
    llmProviders: [] as string[],
    platform: "",
    apiKey: ""
  });

  const [apiKeyCopied, setApiKeyCopied] = useState(false);
  const [isAgentConnected, setIsAgentConnected] = useState(false);
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [keyGenerated, setKeyGenerated] = useState(false);

  const generateApiKey = async () => {
    setIsGeneratingKey(true);
    try {
      const clientId = `${setupData.agentName.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`;
      const response = await apiClient.generateApiKey({
        client_id: clientId,
        client_name: setupData.agentName || 'Agent Setup',
        permissions: ['agent:read', 'agent:write', 'analytics:read'],
        rate_limit_per_minute: 1000
      });
      
      setSetupData(prev => ({ ...prev, apiKey: response.api_key }));
      setKeyGenerated(true);
    } catch (error) {
      console.error('Failed to generate API key:', error);
      // Fallback to local generation if backend fails
      const key = `sk-${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
      setSetupData(prev => ({ ...prev, apiKey: key }));
      setKeyGenerated(true);
    } finally {
      setIsGeneratingKey(false);
    }
  };

  useEffect(() => {
    if (currentStep === "sdk-setup" && !setupData.apiKey) {
      generateApiKey();
    }
  }, [currentStep, setupData.apiKey]);

  const copyApiKey = () => {
    navigator.clipboard.writeText(setupData.apiKey);
    setApiKeyCopied(true);
    setTimeout(() => setApiKeyCopied(false), 2000);
  };

  const handleNext = () => {
    const stepFlow: Record<SetupStep, SetupStep> = {
      "agent-type": setupData.agentType === "coded" ? "agent-details" : "platform-choice",
      "agent-details": "llm-provider",
      "llm-provider": "sdk-setup",
      "platform-choice": "complete",
      "sdk-setup": "complete",
      "complete": "complete"
    };

    const nextStep = stepFlow[currentStep];
    if (nextStep === "complete" && !setupData.apiKey) {
      generateApiKey();
    }
    setCurrentStep(nextStep);
  };

  const handleCompleteSetup = async () => {
    try {
      // Create agent in database
      const response = await apiClient.agents.create({
        agentName: setupData.agentName,
        agentDescription: setupData.agentDescription,
        agentType: setupData.agentType,
        agentUseCase: setupData.agentUseCase,
        llmProviders: setupData.llmProviders,
        platform: setupData.platform
      });

      console.log('Agent created successfully:', response);
      navigate('/dashboard');
    } catch (error) {
      console.error('Failed to create agent:', error);
      // Still navigate to dashboard even if creation fails
    navigate('/dashboard');
    }
  };

  const platforms = [
    "Dialogflow",
    "Microsoft Bot Framework", 
    "Amazon Lex",
    "Rasa",
    "Botpress",
    "Voiceflow",
    "Zapier",
    "N&N"
  ];

  const renderStep = () => {
    switch (currentStep) {
      case "agent-type":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
                <Bot className="h-8 w-8 text-primary" />
              </div>
              <CardTitle className="text-2xl sm:text-3xl">Agent Type</CardTitle>
              <CardDescription className="text-base sm:text-lg">
                How is your AI agent built?
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 sm:gap-6">
                <Button
                  variant={setupData.agentType === "coded" ? "default" : "outline"}
                  className="w-full h-24 sm:h-28 flex flex-col space-y-3 text-left"
                  onClick={() => setSetupData(prev => ({ ...prev, agentType: "coded" }))}
                >
                  <Code className="h-8 w-8" />
                  <div>
                    <span className="text-lg font-semibold">Coded Platform</span>
                    <p className="text-sm opacity-70 mt-1">Custom built with APIs and SDKs</p>
                  </div>
                </Button>
                <Button
                  variant={setupData.agentType === "no-code" ? "default" : "outline"}
                  className="w-full h-24 sm:h-28 flex flex-col space-y-3 text-left"
                  onClick={() => setSetupData(prev => ({ ...prev, agentType: "no-code" }))}
                >
                  <Smartphone className="h-8 w-8" />
                  <div>
                    <span className="text-lg font-semibold">No-Code Platform</span>
                    <p className="text-sm opacity-70 mt-1">Built with visual tools and platforms</p>
                  </div>
                </Button>
              </div>
              <Button 
                onClick={handleNext} 
                className="w-full h-12 text-base font-semibold mt-8"
                disabled={!setupData.agentType}
              >
                Continue
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </CardContent>
          </Card>
        );

      case "agent-details":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <CardTitle className="text-2xl sm:text-3xl">Agent Details</CardTitle>
              <CardDescription className="text-base sm:text-lg">
                Tell us about your AI agent
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-3">
                <Label htmlFor="agentName" className="text-base font-medium">Agent Name</Label>
                <Input
                  id="agentName"
                  placeholder="My AI Assistant"
                  value={setupData.agentName}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentName: e.target.value }))}
                  className="h-12 text-base"
                />
              </div>
              <div className="space-y-3">
                <Label htmlFor="agentDescription" className="text-base font-medium">Description</Label>
                <Textarea
                  id="agentDescription"
                  placeholder="Describe what your agent does and its capabilities..."
                  value={setupData.agentDescription}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentDescription: e.target.value }))}
                  className="min-h-24 text-base resize-none"
                  rows={4}
                />
              </div>
              <div className="space-y-3">
                <Label htmlFor="agentUseCase" className="text-base font-medium">Primary Use Case</Label>
                <Input
                  id="agentUseCase"
                  placeholder="Customer support, sales automation, content generation..."
                  value={setupData.agentUseCase}
                  onChange={(e) => setSetupData(prev => ({ ...prev, agentUseCase: e.target.value }))}
                  className="h-12 text-base"
                />
              </div>
              <Button 
                onClick={handleNext} 
                className="w-full h-12 text-base font-semibold mt-8"
                disabled={!setupData.agentName || !setupData.agentDescription}
              >
                Continue
                <ArrowRight className="ml-2 h-5 w-5" />
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
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <CardTitle className="text-2xl sm:text-3xl">LLM Providers</CardTitle>
              <CardDescription className="text-base sm:text-lg">
                Select the AI providers you're using (multiple selection allowed)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                {["OpenAI", "Anthropic", "Google Gemini",].map((provider) => (
                  <div key={provider} className="flex items-center space-x-4 p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                    <Checkbox
                      id={provider}
                      checked={setupData.llmProviders.includes(provider)}
                      onCheckedChange={(checked) => handleProviderToggle(provider, checked as boolean)}
                    />
                    <Label htmlFor={provider} className="flex-1 cursor-pointer font-medium text-base">
                      {provider}
                    </Label>
                  </div>
                ))}
              </div>
              
              {setupData.llmProviders.length > 0 && (
                <div className="p-4 bg-muted/50 rounded-lg">
                  <p className="text-base font-medium mb-3">Selected providers:</p>
                  <div className="flex flex-wrap gap-2">
                    {setupData.llmProviders.map(provider => (
                      <Badge key={provider} variant="secondary" className="text-sm">{provider}</Badge>
                    ))}
                  </div>
                </div>
              )}
              
              <Button 
                onClick={handleNext} 
                className="w-full h-12 text-base font-semibold mt-8"
                disabled={setupData.llmProviders.length === 0}
              >
                Continue
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </CardContent>
          </Card>
        );

      case "platform-choice":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <CardTitle className="text-2xl sm:text-3xl">Platform Selection</CardTitle>
              <CardDescription className="text-base sm:text-lg">
                Which no-code platform are you using?
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {platforms.map((platform) => (
                  <Button
                    key={platform}
                    variant={setupData.platform === platform ? "default" : "outline"}
                    className="h-16 flex flex-col justify-center text-base"
                    onClick={() => setSetupData(prev => ({ ...prev, platform }))}
                  >
                    <span>{platform}</span>
                  </Button>
                ))}
              </div>
              {!keyGenerated ? (
                <Button 
                  onClick={generateApiKey}
                  className="w-full h-12 text-base font-semibold mt-8"
                  disabled={!setupData.platform || isGeneratingKey}
                >
                  {isGeneratingKey ? (
                    <>
                      <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                      Generating API Key...
                    </>
                  ) : (
                    <>
                      Generate API Key
                      <Key className="ml-2 h-5 w-5" />
                    </>
                  )}
                </Button>
              ) : (
                <div className="space-y-6 mt-8">
                  <div>
                    <Label htmlFor="generated-api-key" className="text-sm font-medium mb-2 block">
                      Your API Key
                    </Label>
                    <Alert className="mb-4">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription className="text-sm">
                        <strong>Important:</strong> Store this key securely. It will not be shown again after setup.
                      </AlertDescription>
                    </Alert>
                    <div className="flex gap-2">
                      <Input
                        id="generated-api-key"
                        value={setupData.apiKey}
                        readOnly
                        className="font-mono text-sm"
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={copyApiKey}
                      >
                        {apiKeyCopied ? (
                          <CheckCircle className="h-4 w-4 text-green-600" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                  <Button 
                    onClick={handleCompleteSetup}
                    className="w-full h-12 text-base font-semibold"
                  >
                    Complete Setup
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        );

      case "sdk-setup":
        return (
          <Card className="w-full max-w-4xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <CardTitle className="text-2xl sm:text-3xl">SDK Integration</CardTitle>
              <CardDescription className="text-base sm:text-lg">
                Follow these steps to integrate our analytics SDK
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-8">
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-start space-y-4 sm:space-y-0 sm:space-x-4">
                  <Badge className="w-8 h-8 flex items-center justify-center text-base font-bold">1</Badge>
                  <div className="flex-1">
                    <h4 className="font-semibold text-lg mb-3">Install the SDK</h4>
                    <div className="p-4 bg-muted rounded-lg font-mono text-sm overflow-x-auto">
                      npm install @analytics-dashboard/sdk
                    </div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-start space-y-4 sm:space-y-0 sm:space-x-4">
                  <Badge className="w-8 h-8 flex items-center justify-center text-base font-bold">2</Badge>
                  <div className="flex-1">
                    <h4 className="font-semibold text-lg mb-3">Initialize in your code</h4>
                    <div className="p-4 bg-muted rounded-lg font-mono text-sm overflow-x-auto">
                       {`import { AnalyticsSDK } from '@analytics-dashboard/sdk';

const analytics = new AnalyticsSDK({
  apiKey: 'YOUR_API_KEY',
  providers: [${setupData.llmProviders.map(p => `'${p}'`).join(', ')}]
});`}
                    </div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-start space-y-4 sm:space-y-0 sm:space-x-4">
                  <Badge className="w-8 h-8 flex items-center justify-center text-base font-bold">3</Badge>
                  <div className="flex-1">
                    <h4 className="font-semibold text-lg mb-3">Your API Key</h4>
                    <Alert className="mb-4">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription className="text-sm">
                        <strong>Important:</strong> Store this in your .env file as BACKEND_API_KEY. 
                        This key will not be available after 1 hour for security reasons.
                      </AlertDescription>
                    </Alert>

                    <div className="mb-4">
                      <Label htmlFor="api-key" className="text-sm font-medium mb-2 block">
                        Your API Key
                      </Label>
                      <div className="flex gap-2">
                        <Input
                          id="api-key"
                          value={setupData.apiKey}
                          readOnly
                          className="font-mono text-sm"
                          placeholder="Click generate to create API key"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="icon"
                          onClick={() => {
                            navigator.clipboard.writeText(setupData.apiKey);
                            setApiKeyCopied(true);
                            setTimeout(() => setApiKeyCopied(false), 2000);
                          }}
                          disabled={!setupData.apiKey}
                        >
                          {apiKeyCopied ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </div>

                    <div className="mt-4">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className={`transition-all duration-200 ${
                          isAgentConnected 
                            ? 'bg-green-500 hover:bg-green-600 text-white border-green-500' 
                            : 'bg-red-500 hover:bg-red-600 text-white border-red-500'
                        }`}
                        onClick={() => setIsAgentConnected(!isAgentConnected)}
                      >
                        <div className={`w-2 h-2 rounded-full mr-2 ${
                          isAgentConnected ? 'bg-white' : 'bg-white'
                        }`} />
                        {isAgentConnected ? 'Agent Connected' : 'Agent Disconnected'}
                      </Button>
                    </div>

                  </div>
                </div>
              </div>

              <Button 
                onClick={handleCompleteSetup}
                className="w-full h-12 text-base font-semibold"
              >
                Complete Setup
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </CardContent>
          </Card>
        );

      case "complete":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardContent className="text-center py-12">
              <div className="mx-auto w-20 h-20 bg-success/10 rounded-full flex items-center justify-center mb-6">
                <CheckCircle className="h-10 w-10 text-success" />
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold mb-4">Agent Setup Complete!</h1>
              <p className="text-base sm:text-lg text-muted-foreground mb-8 max-w-md mx-auto">
                Your agent "{setupData.agentName}" is now configured and ready for monitoring.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center max-w-md mx-auto">
                <Button asChild className="h-12 text-base font-semibold">
                  <Link to="/dashboard">
                    View Dashboard
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Link>
                </Button>
                <Button variant="outline" asChild className="h-12 text-base font-semibold">
                  <Link to="/agent-setup">
                    Add Another Agent
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        );

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4 sm:px-6 lg:px-8">
      <div className="w-full max-w-5xl">
        {renderStep()}
      </div>
    </div>
  );
};

export default AgentSetup;