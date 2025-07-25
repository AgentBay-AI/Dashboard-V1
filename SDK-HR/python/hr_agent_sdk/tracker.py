import time
import requests
import json
from typing import Optional, Dict, Any, ContextManager
from contextlib import contextmanager
from .metrics import MetricsCollector
from .health import HealthMonitor
from .security import SecurityMonitor

class AgentTracker:
    """
    Main tracker class for AI agents to report metrics to HR Agent Platform
    """
    
    def __init__(
        self, 
        agent_id: str, 
        api_key: str, 
        base_url: str = "https://hr-agent-frontend-1080649900100.me-central1.run.app/api"
    ):
        self.agent_id = agent_id
        self.api_key = api_key
        self.base_url = base_url
        self.metrics = MetricsCollector()
        self.health = HealthMonitor()
        self.security = SecurityMonitor()
        
        # Headers for API requests
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "hr-agent-sdk/0.1.0"
        }
    
    @contextmanager
    def track_request(self, operation_name: str = "ai_request") -> ContextManager[Dict[str, Any]]:
        """
        Context manager to track AI requests automatically
        
        Usage:
        with tracker.track_request("chat_completion") as context:
            response = openai.ChatCompletion.create(...)
            context["prompt_tokens"] = response.usage.prompt_tokens
            context["completion_tokens"] = response.usage.completion_tokens
        """
        start_time = time.time()
        context = {
            "operation": operation_name,
            "start_time": start_time,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cost": 0.0,
            "model": "",
            "provider": ""
        }
        
        try:
            yield context
            
            # Calculate metrics
            duration = time.time() - start_time
            
            # Log successful request
            self.log_request(
                prompt_tokens=context.get("prompt_tokens", 0),
                completion_tokens=context.get("completion_tokens", 0),
                cost=context.get("cost", 0.0),
                latency=duration,
                model=context.get("model", ""),
                provider=context.get("provider", ""),
                success=True
            )
            
        except Exception as e:
            # Log failed request
            duration = time.time() - start_time
            self.log_error(str(e), duration, operation_name)
            raise
    
    def log_request(
        self, 
        prompt_tokens: int, 
        completion_tokens: int, 
        cost: float, 
        latency: float,
        model: str = "",
        provider: str = "",
        success: bool = True
    ):
        """Log a single AI request with its metrics"""
        
        payload = {
            "agent_id": self.agent_id,
            "type": "request",
            "timestamp": time.time(),
            "data": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "cost": cost,
                "latency": latency,
                "model": model,
                "provider": provider,
                "success": success
            }
        }
        
        # Update local metrics
        self.metrics.update_tokens(prompt_tokens, completion_tokens, cost)
        self.metrics.update_latency(latency)
        
        # Send to API
        self._send_metrics(payload)
    
    def log_error(self, error_message: str, latency: float = 0.0, operation: str = ""):
        """Log an error that occurred during agent operation"""
        
        payload = {
            "agent_id": self.agent_id,
            "type": "error",
            "timestamp": time.time(),
            "data": {
                "error": error_message,
                "latency": latency,
                "operation": operation
            }
        }
        
        # Update local metrics
        self.metrics.increment_errors()
        
        # Send to API
        self._send_metrics(payload)
    
    def log_health(
        self, 
        status: str = "healthy", 
        memory_usage: Optional[float] = None,
        cpu_usage: Optional[float] = None
    ):
        """Log health status of the agent"""
        
        # Update health monitor
        self.health.update_status(status, memory_usage, cpu_usage)
        
        payload = {
            "agent_id": self.agent_id,
            "type": "health",
            "timestamp": time.time(),
            "data": {
                "status": status,
                "uptime": self.health.get_uptime(),
                "memory_usage": memory_usage,
                "cpu_usage": cpu_usage,
                "response_time": self.metrics.get_average_latency()
            }
        }
        
        # Send to API
        self._send_health(payload)
    
    def log_security_event(
        self, 
        event_type: str, 
        description: str, 
        severity: str = "medium",
        source_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        blocked: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a security event"""
        
        # Update security monitor
        event = self.security.log_security_event(
            event_type, description, severity, source_ip, endpoint, blocked, metadata
        )
        
        payload = {
            "agent_id": self.agent_id,
            "type": "security",
            "timestamp": time.time(),
            "data": event
        }
        
        # Send to API
        self._send_metrics(payload)
    
    def log_compliance_event(
        self,
        compliance_type: str,
        event_description: str,
        data_processed: Optional[Dict[str, Any]] = None,
        user_consent: Optional[bool] = None,
        encryption_status: bool = True,
        data_location: str = "cloud",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a compliance event (GDPR, HIPAA, etc.)"""
        
        # Update security monitor
        event = self.security.log_compliance_event(
            compliance_type, event_description, data_processed, 
            user_consent, encryption_status, data_location, metadata
        )
        
        payload = {
            "agent_id": self.agent_id,
            "type": "compliance",
            "timestamp": time.time(),
            "data": event
        }
        
        # Send to API
        self._send_metrics(payload)
    
    def analyze_request_security(self, request_data: str, user_input: str = "") -> Dict[str, Any]:
        """Analyze request for security threats"""
        return self.security.analyze_request_security(request_data, user_input)
    
    def check_data_privacy(self, text: str) -> Dict[str, Any]:
        """Check text for potential privacy violations"""
        return self.security.check_data_privacy(text)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        return {
            "total_tokens": self.metrics.total_tokens,
            "total_cost": self.metrics.total_cost,
            "request_count": self.metrics.request_count,
            "error_count": self.metrics.error_count,
            "average_latency": self.metrics.get_average_latency(),
            "error_rate": self.metrics.get_error_rate(),
            "uptime": self.health.get_uptime(),
            "security": self.security.get_security_summary()
        }
    
    def _send_metrics(self, payload: Dict[str, Any]):
        """Send metrics to the API endpoint"""
        try:
            response = requests.post(
                f"{self.base_url}/agents/log",
                headers=self.headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send metrics: {e}")
    
    def _send_health(self, payload: Dict[str, Any]):
        """Send health data to the API endpoint"""
        try:
            response = requests.post(
                f"{self.base_url}/agents/health",
                headers=self.headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send health data: {e}") 