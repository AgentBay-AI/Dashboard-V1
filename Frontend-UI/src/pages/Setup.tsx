import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Building2, Bot, ArrowRight } from "lucide-react";
import { useNavigate } from "react-router-dom";

type SetupStep = "choice";

const Setup = () => {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState<SetupStep>("choice");
  const [setupData, setSetupData] = useState({
    choice: "",
  });

  const handleNext = () => {
    console.log("Navigating to:", setupData.choice); // Debug log
    if (setupData.choice === "organization") {
      navigate("/organisation");
    } else if (setupData.choice === "agent") {
      navigate("/agent-setup");
    }
  };

  const handleChoiceClick = (choice: string) => {
    console.log("Selected choice:", choice); // Debug log
    setSetupData(prev => ({ ...prev, choice }));
  };

  const renderStep = () => {
    switch (currentStep) {
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
                onClick={() => handleChoiceClick("organization")}
              >
                <Building2 className="h-8 w-8" />
                <span>Create Organization</span>
              </Button>
              <Button
                variant={setupData.choice === "agent" ? "default" : "outline"}
                className="w-full h-20 flex flex-col space-y-2"
                onClick={() => handleChoiceClick("agent")}
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

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-4xl">
        {renderStep()}
      </div>
    </div>
  );
};

export default Setup;
