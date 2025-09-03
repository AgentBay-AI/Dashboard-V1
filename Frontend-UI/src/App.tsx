import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import { ThemeProvider } from "./components/ThemeProvider";
import Index from "@/pages/Index.tsx";
import NewDashboard from "@/pages/newdasboard.tsx";
import Setup from "@/pages/Setup.tsx";
import AgentSetup from "@/pages/Agentsetup.tsx";
import OrganizationSetup from "@/pages/Organisationsetup.tsx";
import NotFound from "@/pages/NotFound.tsx";
import { SignedIn, SignedOut, SignIn, useAuth, useUser } from "@clerk/clerk-react";
import axios from 'axios';
import { useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const queryClient = new QueryClient();

function ClerkSync() {
  const { isSignedIn, getToken } = useAuth();
  const { user } = useUser();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!isSignedIn || !user) return;
      try {
        const email = user.primaryEmailAddress?.emailAddress || user.emailAddresses[0]?.emailAddress || '';
        if (!email) return;
        const full_name = user.fullName || user.firstName || '';
        const clerk_user_id = user.id;
        const baseURL = (import.meta.env.VITE_BACKEND_URL as string | undefined) || 'http://localhost:8081/api';
        // Request a token from the custom Clerk JWT template (default 'backend')
        const template = (import.meta.env.VITE_CLERK_JWT_TEMPLATE as string | undefined) || 'backend';
        const token = await getToken({ template });
        if (!token) return;
        const res = await axios.post(
          `${baseURL}/auth/clerk/sync`,
          { clerk_user_id, email, full_name },
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (cancelled) return;
        const data = res.data?.data || {};
        if (data.client_id) localStorage.setItem('client_id', data.client_id);
        if (data.dashboard_key) localStorage.setItem('dashboard_api_key', data.dashboard_key);
        // Ensure frontend API targets the same backend
        localStorage.setItem('backend_url', baseURL);
        localStorage.setItem('client_sync_ok', '1');
      } catch (e) {
        console.warn('Clerk sync failed', e);
      }
    })();
    return () => { cancelled = true; };
  }, [isSignedIn, user?.id, getToken]);

  return null;
}

function SignInRoute() {
  const { isSignedIn, signOut } = useAuth();

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <Card style={{ maxWidth: 520, width: '100%' }}>
        <CardHeader>
          <CardTitle>Sign in to access your dashboard</CardTitle>
        </CardHeader>
        <CardContent>
          <SignedOut>
            <SignIn afterSignInUrl="/dashboard" />
          </SignedOut>
          <SignedIn>
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">You're already signed in.</p>
              <div className="flex gap-2">
                <Link to="/dashboard"><Button>Go to Dashboard</Button></Link>
                <Button variant="outline" onClick={async () => { await signOut(); }}>Switch account</Button>
              </div>
            </div>
          </SignedIn>
        </CardContent>
      </Card>
    </div>
  );
}

const App = () => {
  return (
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
                      <Navigate to="/sign-in" replace />
                    </SignedOut>
                    <SignedIn>
                      <ClerkSync />
                      <NewDashboard />
                    </SignedIn>
                  </div>
                }
              />
              <Route path="/sign-in" element={<SignInRoute />} />
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
};

export default App;
