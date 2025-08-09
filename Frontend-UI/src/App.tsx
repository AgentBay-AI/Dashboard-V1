import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "./components/ThemeProvider";
import Index from "@/pages/Index.tsx";
import NewDashboard from "@/pages/newdasboard.tsx";
import Setup from "@/pages/Setup.tsx";
import AgentSetup from "@/pages/Agentsetup.tsx";
import OrganizationSetup from "@/pages/Organisationsetup.tsx";
import NotFound from "@/pages/NotFound.tsx";
import { SignedIn, SignedOut, SignIn } from "@clerk/clerk-react";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider defaultTheme="light" storageKey="analytics-dashboard-theme">
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route
              path="/dashboard"
              element={
                <div>
                  <SignedOut>
                    <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}>
                      <SignIn redirectUrl="/dashboard" />
                    </div>
                  </SignedOut>
                  <SignedIn>
                    <NewDashboard />
                  </SignedIn>
                </div>
              }
            />
            <Route path="/setup" element={<Setup />} />
            <Route path="/agent-setup" element={<AgentSetup />} />
            <Route path="/organization-setup" element={<OrganizationSetup />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
