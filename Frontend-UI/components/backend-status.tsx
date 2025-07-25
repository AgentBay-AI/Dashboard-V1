import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

interface BackendStatus {
  connected: boolean;
  status?: string;
  version?: string;
  environment?: string;
  uptime?: number;
  error?: string;
}

export function BackendStatus() {
  const [status, setStatus] = useState<BackendStatus>({ connected: false });
  const [loading, setLoading] = useState(true);

  const checkBackendHealth = async () => {
    try {
      setLoading(true);
      
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080';
      const response = await fetch(`${backendUrl}/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setStatus({
          connected: true,
          status: data.status,
          version: data.version,
          environment: data.environment,
          uptime: data.uptime,
        });
      } else {
        setStatus({
          connected: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
        });
      }
    } catch (error) {
      setStatus({
        connected: false,
        error: error instanceof Error ? error.message : 'Connection failed',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkBackendHealth();
    
    // Check every 30 seconds
    const interval = setInterval(checkBackendHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-lg">Backend Status</CardTitle>
            <CardDescription>
              Connection to AI Agent Operations Platform API
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={status.connected ? 'default' : 'destructive'}>
              {status.connected ? '🟢 Connected' : '🔴 Disconnected'}
            </Badge>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={checkBackendHealth}
              disabled={loading}
            >
              {loading ? '⟳' : '🔄'} Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {status.connected ? (
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Status:</span>
              <span className="ml-2 capitalize">{status.status}</span>
            </div>
            <div>
              <span className="font-medium">Version:</span>
              <span className="ml-2">{status.version}</span>
            </div>
            <div>
              <span className="font-medium">Environment:</span>
              <span className="ml-2 capitalize">{status.environment}</span>
            </div>
            <div>
              <span className="font-medium">Uptime:</span>
              <span className="ml-2">
                {status.uptime ? formatUptime(status.uptime) : 'Unknown'}
              </span>
            </div>
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">
            <p className="mb-2">❌ Unable to connect to backend</p>
            {status.error && (
              <p className="text-red-600">
                <strong>Error:</strong> {status.error}
              </p>
            )}
            <p className="mt-2 text-xs">
              Expected backend URL: {process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080'}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
} 