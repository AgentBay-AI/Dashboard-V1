import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ArrowRight, Building2, CheckCircle } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import axios from 'axios';
import { useAuth } from "@clerk/clerk-react";
import { useToast } from "@/components/ui/use-toast";
import { apiClient } from "@/lib/api";

type SetupStep = "details" | "success";

const OrganizationSetup = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState<SetupStep>("details");
  const [setupData, setSetupData] = useState({
    orgName: "",
    orgType: "",
    orgDescription: "",
    email: "",
  });

  const { getToken, isSignedIn } = useAuth();

  const handleNext = async () => {
    if (currentStep === "details") {
      setIsLoading(true);
      try {
        // Prefer JWT-authenticated org creation so it binds to the user's client_id
        let response: any = null;
        try {
          const template = (import.meta.env.VITE_CLERK_JWT_TEMPLATE as string | undefined) || 'backend';
          const token = isSignedIn ? await getToken({ template }) : undefined;
          const baseURL = (localStorage.getItem('backend_url') || (import.meta.env.VITE_BACKEND_URL as string | undefined) || 'http://localhost:8081/api');
          if (token) {
            const { data } = await axios.post(`${baseURL}/setup/organization`, {
              email: setupData.email,
              orgName: setupData.orgName,
              orgType: setupData.orgType,
              orgDescription: setupData.orgDescription,
            }, { headers: { Authorization: `Bearer ${token}` } });
            response = data;
          }
        } catch {}

        // Fallback without JWT (dev/non-auth flows)
        if (!response) {
          response = await apiClient.setupOrg.create({
            email: setupData.email,
            orgName: setupData.orgName,
            orgType: setupData.orgType,
            orgDescription: setupData.orgDescription,
          });
        }
        if (!response?.success) throw new Error(response?.error || 'Failed to create organization');
        const organization = response?.data?.organization;
        const clientId = response?.data?.client_id;
        if (clientId) localStorage.setItem('client_id', clientId);
        // Ensure backend_url is set so the dashboard can proceed
        try {
          const existingBase = localStorage.getItem('backend_url');
          if (!existingBase) {
            const envBase = (import.meta.env.VITE_BACKEND_URL as string | undefined) || 'http://localhost:8081/api';
            localStorage.setItem('backend_url', envBase);
          }
        } catch {}
        setCurrentStep("success");
        toast({ title: "Organization Created", description: "Your organization has been created successfully." });
      } catch (error: unknown) {
        console.error('Error creating organization:', error);
        toast({ variant: "destructive", title: "Error", description: error instanceof Error ? error.message : "Failed to create organization. Please try again." });
      } finally {
        setIsLoading(false);
      }
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case "details":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardHeader className="text-center pb-6">
              <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
                <Building2 className="h-8 w-8 text-primary" />
              </div>
              <CardTitle className="text-2xl sm:text-3xl">Create Organization</CardTitle>
              <CardDescription className="text-base sm:text-lg">Set up your organization to manage AI agents and analytics</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-6 sm:gap-8">
                <div className="space-y-3">
                  <Label htmlFor="orgName" className="text-base font-medium">Organization Name</Label>
                  <Input id="orgName" placeholder="Acme Corp" value={setupData.orgName} onChange={(e) => setSetupData(prev => ({ ...prev, orgName: e.target.value }))} className="h-12 text-base" />
                </div>
                <div className="space-y-3">
                  <Label htmlFor="email" className="text-base font-medium">Contact Email</Label>
                  <Input id="email" type="email" placeholder="admin@acme.com" value={setupData.email} onChange={(e) => setSetupData(prev => ({ ...prev, email: e.target.value }))} className="h-12 text-base" />
                </div>
                <div className="space-y-3">
                  <Label htmlFor="orgType" className="text-base font-medium">Organization Type</Label>
                  <Select value={setupData.orgType} onValueChange={(value) => setSetupData(prev => ({ ...prev, orgType: value }))}>
                    <SelectTrigger className="h-12 text-base">
                      <SelectValue placeholder="Select organization type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="startup">Startup</SelectItem>
                      <SelectItem value="enterprise">Enterprise</SelectItem>
                      <SelectItem value="agency">Digital Agency</SelectItem>
                      <SelectItem value="consulting">Consulting Firm</SelectItem>
                      <SelectItem value="nonprofit">Non-profit</SelectItem>
                      <SelectItem value="education">Education</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-3">
                  <Label htmlFor="orgDescription" className="text-base font-medium">Description</Label>
                  <Textarea id="orgDescription" placeholder="Tell us about your organization and how you plan to use AI agents..." value={setupData.orgDescription} onChange={(e) => setSetupData(prev => ({ ...prev, orgDescription: e.target.value }))} className="min-h-24 text-base resize-none" rows={4} />
                </div>
              </div>
              <div className="pt-6">
                <Button onClick={handleNext} className="w-full h-12 text-base font-semibold" disabled={!setupData.orgName || !setupData.orgType || !setupData.email || isLoading}>
                  Create Organization
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      case "success":
        return (
          <Card className="w-full max-w-2xl mx-auto animate-fade-in">
            <CardContent className="text-center py-12">
              <div className="mx-auto w-20 h-20 bg-success/10 rounded-full flex items-center justify-center mb-6">
                <CheckCircle className="h-10 w-10 text-success" />
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold mb-4">Organization Created Successfully!</h1>
              <p className="text-base sm:text-lg text-muted-foreground mb-8 max-w-md mx-auto">Your organization "{setupData.orgName}" has been set up. Now you can add your first AI agent.</p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center max-w-md mx-auto">
                <Button asChild className="h-12 text-base font-semibold"><Link to="/agent-setup">Add First Agent<ArrowRight className="ml-2 h-5 w-5" /></Link></Button>
                <Button variant="outline" asChild className="h-12 text-base font-semibold"><Link to="/dashboard">View Dashboard</Link></Button>
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
      <div className="w-full max-w-4xl">{renderStep()}</div>
    </div>
  );
};

export default OrganizationSetup;
