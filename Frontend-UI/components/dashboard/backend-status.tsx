"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { CheckCircle, XCircle, AlertCircle, Loader2 } from "lucide-react"

export function BackendStatus() {
  const [status, setStatus] = useState<'checking' | 'connected' | 'disconnected' | 'error'>('checking')
  const [dbStatus, setDbStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown')
  const [lastCheck, setLastCheck] = useState<Date>(new Date())

  const checkBackendHealth = async () => {
    try {
      setStatus('checking')
      const backendUrl = 'http://localhost:8080'
      
      // Check backend health
      const healthRes = await fetch(`${backendUrl}/health`, { 
        signal: AbortSignal.timeout(5000) 
      })
      
      if (healthRes.ok) {
        setStatus('connected')
        
        // Check database connection
        const dbRes = await fetch(`${backendUrl}/api/frontend/organizations`, {
          signal: AbortSignal.timeout(5000)
        })
        
        if (dbRes.ok) {
          setDbStatus('connected')
        } else {
          setDbStatus('disconnected')
        }
      } else {
        setStatus('disconnected')
      }
      
      setLastCheck(new Date())
    } catch (error) {
      console.error('Backend health check failed:', error)
      setStatus('error')
      setDbStatus('unknown')
      setLastCheck(new Date())
    }
  }

  useEffect(() => {
    checkBackendHealth()
    
    // Check every 30 seconds
    const interval = setInterval(checkBackendHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  const getStatusIcon = () => {
    switch (status) {
      case 'checking':
        return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
      case 'connected':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'disconnected':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'error':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />
    }
  }

  const getStatusColor = () => {
    switch (status) {
      case 'checking':
        return 'blue'
      case 'connected':
        return 'green'
      case 'disconnected':
        return 'red'
      case 'error':
        return 'yellow'
    }
  }

  const getDbStatusColor = () => {
    switch (dbStatus) {
      case 'connected':
        return 'green'
      case 'disconnected':
        return 'red'
      default:
        return 'gray'
    }
  }

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          {getStatusIcon()}
          System Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Backend API</span>
          <Badge variant="outline" className={`text-${getStatusColor()}-600 border-${getStatusColor()}-300`}>
            {status === 'checking' ? 'Checking...' : 
             status === 'connected' ? 'Connected' :
             status === 'disconnected' ? 'Disconnected' : 'Error'}
          </Badge>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Database</span>
          <Badge variant="outline" className={`text-${getDbStatusColor()}-600 border-${getDbStatusColor()}-300`}>
            {dbStatus === 'connected' ? 'Connected' :
             dbStatus === 'disconnected' ? 'Disconnected' : 'Unknown'}
          </Badge>
        </div>
        
        <div className="text-xs text-muted-foreground">
          Last check: {lastCheck.toLocaleTimeString()}
        </div>
        
        <button 
          onClick={checkBackendHealth}
          className="text-xs text-blue-600 hover:text-blue-800 underline"
          disabled={status === 'checking'}
        >
          {status === 'checking' ? 'Checking...' : 'Check Now'}
        </button>
      </CardContent>
    </Card>
  )
} 