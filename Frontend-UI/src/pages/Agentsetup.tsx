import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/ui/use-toast";
import { 
  ArrowRight, 
  Bot, 
  Code, 
  Smartphone, 
  Key, 
  AlertTriangle,
  Copy,
  CheckCircle,
  Wifi,
  WifiOff
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

type SetupStep = "agent-type" | "agent-details" | "llm-provider" | "sdk-setup" | "platform-choice" | "complete";

const AgentSetup = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
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
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'checking'>('disconnected');

  useEffect(() => {
    if (!setupData.apiKey) {
      generateApiKey();
    }
  }, []);

  const generateApiKey = () => {
    const key = `sk-${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
    setSetupData(prev => ({ ...prev, apiKey: key }));
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(setupData.apiKey);
    setApiKeyCopied(true);
    setTimeout(() => setApiKeyCopied(false), 2000);
  };

  const checkConnection = async () => {
    if (!setupData.apiKey) {
      toast({
        title: "No API Key",
        description: "Please generate an API key first.",
        variant: "destructive"
      });
      return;
    }

    setConnectionStatus('checking');
    
    try {
      // Simulate API call to check connection
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // For demo purposes, randomly succeed or fail
      const isConnected = Math.random() > 0.3;
      
      if (isConnected) {
        setConnectionStatus('connected');
        toast({
          title: "Connection Successful",
          description: "Your agent is connected and ready to use."
        });
      } else {
        setConnectionStatus('disconnected');
        toast({
          title: "Connection Failed",
          description: "Unable to connect to the agent. Please check your configuration.",
          variant: "destructive"
        });
      }
    } catch (error) {
      setConnectionStatus('disconnected');
      toast({
        title: "Connection Error",
        description: "An error occurred while testing the connection.",
        variant: "destructive"
      });
    }
    setTimeout(() => setApiKeyCopied(false), 2000);
  };

  const handleNext = async () => {
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

    // If we're moving to complete, create the agent in the backend
    if (nextStep === "complete" && !isLoading) {
      setIsLoading(true);
      try {
        const response = await axios.post(
          `${import.meta.env.VITE_BACKEND_URL}/agents`,
          {
            agentName: setupData.agentName,
            agentDescription: setupData.agentDescription,
            agentType: setupData.agentType,
            agentUseCase: setupData.agentUseCase,

            llmProviders: setupData.llmProviders,
            platform: setupData.platform,
            status: "active",
            sdk_version: "1.0.0"
          },
          {
            headers: {
              Authorization: `Bearer ${import.meta.env.VITE_API_KEY}`
            }
          }
        );

        if (response.data.success) {
          toast({
            title: "Agent Created",
            description: "Your agent has been created successfully.",
          });
          setCurrentStep(nextStep);
        }
      } catch (error: unknown) {
        console.error('Error creating agent:', error);
        toast({
          variant: "destructive",
          title: "Error",
          description: error instanceof Error ? error.message : "Failed to create agent. Please try again.",
        });
      } finally {
        setIsLoading(false);
      }
    } else {
      setCurrentStep(nextStep);
    }
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
                {["OpenAI", "Anthropic", "Google Gemini"].map((provider) => (
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
              <Button 
                onClick={handleNext}
                className="w-full h-12 text-base font-semibold mt-8"
                disabled={!setupData.platform}
              >
                Generate API Key
                <Key className="ml-2 h-5 w-5" />
              </Button>
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
                    <div className="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-3">
                      <Input 
                        value={setupData.apiKey} 
                        readOnly 
                        className="font-mono text-sm flex-1"
                      />
                      <Button
                        variant="outline"
                        onClick={copyApiKey}
                        className="sm:w-auto"
                      >
                        {apiKeyCopied ? <CheckCircle className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
                        {apiKeyCopied ? "Copied!" : "Copy"}
                      </Button>
                    </div>
                    
                    {/* Connection Status */}
                    <div className="mt-6 p-4 border rounded-lg bg-muted/50">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {connectionStatus === 'connected' ? (
                            <Wifi className="h-4 w-4 text-green-500" />
                          ) : connectionStatus === 'checking' ? (
                            <div className="animate-spin h-4 w-4 border-2 border-primary border-t-transparent rounded-full" />
                          ) : (
                            <WifiOff className="h-4 w-4 text-red-500" />
                          )}
                          <span className="text-sm font-medium">
                            Agent Status: 
                            <Badge 
                              variant={connectionStatus === 'connected' ? 'default' : 'destructive'} 
                              className="ml-2"
                            >
                              {connectionStatus === 'connected' ? 'Connected' : 
                               connectionStatus === 'checking' ? 'Checking...' : 'Disconnected'}
                            </Badge>
                          </span>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={checkConnection}
                          disabled={connectionStatus === 'checking'}
                        >
                          {connectionStatus === 'checking' ? 'Checking...' : 'Test Connection'}
                        </Button>
                      </div>
                      {connectionStatus === 'disconnected' && (
                        <p className="text-xs text-muted-foreground mt-2">
                          Make sure your agent is running and the API key is configured correctly.
                        </p>
                      )}
                      {connectionStatus === 'connected' && (
                        <p className="text-xs text-green-600 mt-2">
                          Your agent is successfully connected and ready to use.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <Button 
                onClick={handleNext}
                className="w-full h-12 text-base font-semibold"
              >
                Complete Setup
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </CardContent>
          </Card>
        );

      case "complete": {
        const instructions = [
          "Install the SDK",
          "Initialize in your code",
          "Your API Key"
        ];
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
                  <Link to="/setup">
                    Setup More
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      }

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