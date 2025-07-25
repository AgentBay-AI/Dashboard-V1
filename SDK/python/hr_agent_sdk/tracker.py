import requests
import time
import uuid
from contextlib import contextmanager
from typing import Optional, Dict, Any, Union
from .metrics import MetricsCollector
from .health import HealthMonitor
from .security import SecurityMonitor


class AgentTracker:
    """
    Main class for tracking AI agent operations, performance, and health.
    
    This class provides a unified interface for logging metrics, health status,
    errors, security events, and compliance data to the HR Agent backend.
    """
    
    def __init__(
        self,
        agent_id: str,
        backend_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize the AgentTracker.
        
        Args:
            agent_id: Unique identifier for the agent
            backend_url: URL of the HR Agent backend API
            api_key: API key for authentication (optional for development)
            timeout: Request timeout in seconds
        """
        self.agent_id = agent_id
        self.backend_url = backend_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        
        # Initialize monitoring components
        self.metrics = MetricsCollector()
        self.health = HealthMonitor()
        self.security = SecurityMonitor()
        
        # Headers for API requests
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'hr-agent-sdk/1.0.0 (agent:{agent_id})'
        }
        
        if self.api_key:
            self.headers['Authorization'] = f'Bearer {self.api_key}'
    
    @contextmanager
    def track_request(self, operation: str = "unknown"):
        """
        Context manager for automatically tracking request metrics.
        
        Args:
            operation: Name of the operation being tracked
            
        Usage:
            with tracker.track_request("openai_completion"):
                # Your AI operation here
                response = openai.completion.create(...)
        """
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Log start of operation
            self.security.analyze_request_security(operation, {
                'request_id': request_id,
                'timestamp': start_time
            })
            
            yield request_id
            
            # Calculate metrics
            latency = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            # Update local metrics
            self.metrics.update_request(latency, success=True)
            
            # Log successful completion
            self.log_request({
                'operation': operation,
                'request_id': request_id,
                'latency': latency,
                'success': True
            })
            
        except Exception as e:
            # Calculate metrics for failed request
            latency = (time.time() - start_time) * 1000
            
            # Update local metrics
            self.metrics.update_request(latency, success=False)
            self.metrics.update_error(str(type(e).__name__))
            
            # Log error
            self.log_error(
                error_type=type(e).__name__,
                error_message=str(e),
                context={
                    'operation': operation,
                    'request_id': request_id,
                    'latency': latency
                }
            )
            
            # Re-raise the exception
            raise
    
    def log_request(self, data: Dict[str, Any]) -> bool:
        """
        Log request metrics to the backend.
        
        Args:
            data: Dictionary containing request metrics
            
        Returns:
            True if successful, False otherwise
        """
        payload = {
            'type': 'metrics',
            'data': {
                'agent_id': self.agent_id,
                'total_tokens': data.get('total_tokens', 0),
                'input_tokens': data.get('input_tokens', 0),
                'output_tokens': data.get('output_tokens', 0),
                'total_cost': data.get('total_cost', 0.0),
                'total_requests': 1,
                'average_latency': data.get('latency', 0.0),
                'success_rate': 100.0 if data.get('success', True) else 0.0
            }
        }
        
        return self._send_request('/api/agents/log', payload)
    
    def log_tokens(self, input_tokens: int, output_tokens: int, cost: float = 0.0) -> bool:
        """
        Log token usage and cost.
        
        Args:
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens generated
            cost: Cost of the operation
            
        Returns:
            True if successful, False otherwise
        """
        total_tokens = input_tokens + output_tokens
        self.metrics.update_tokens(total_tokens, cost)
        
        return self.log_request({
            'total_tokens': total_tokens,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'total_cost': cost,
            'success': True
        })
    
    def log_error(
        self,
        error_type: str,
        error_message: str,
        stack_trace: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        severity: str = "medium"
    ) -> bool:
        """
        Log an error to the backend.
        
        Args:
            error_type: Type/category of the error
            error_message: Error message description
            stack_trace: Full stack trace (optional)
            context: Additional context data (optional)
            severity: Error severity (low, medium, high, critical)
            
        Returns:
            True if successful, False otherwise
        """
        payload = {
            'type': 'error',
            'data': {
                'agent_id': self.agent_id,
                'error_type': error_type,
                'error_message': error_message,
                'stack_trace': stack_trace,
                'context': context,
                'severity': severity
            }
        }
        
        return self._send_request('/api/agents/log', payload)
    
    def log_health(self, status: str = "healthy", **kwargs) -> bool:
        """
        Log health status to the backend.
        
        Args:
            status: Health status (healthy, warning, critical)
            **kwargs: Additional health metrics
            
        Returns:
            True if successful, False otherwise
        """
        system_metrics = self.health.get_system_metrics()
        
        payload = {
            'agent_id': self.agent_id,
            'status': status,
            'uptime': self.health.get_uptime(),
            'response_time': kwargs.get('response_time', 0.0),
            'error_rate': kwargs.get('error_rate', 0.0),
            'cpu_usage': system_metrics.get('cpu_percent'),
            'memory_usage': system_metrics.get('memory_percent')
        }
        
        return self._send_request('/api/agents/health', payload)
    
    def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            description: Description of the event
            severity: Event severity (low, medium, high, critical)
            metadata: Additional event metadata
            
        Returns:
            True if successful, False otherwise
        """
        payload = {
            'type': 'security',
            'data': {
                'agent_id': self.agent_id,
                'event_type': event_type,
                'description': description,
                'severity': severity,
                'metadata': metadata
            }
        }
        
        return self._send_request('/api/agents/log', payload)
    
    def log_compliance_event(
        self,
        compliance_type: str,
        status: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log a compliance event.
        
        Args:
            compliance_type: Type of compliance check
            status: Compliance status (compliant, non_compliant, warning)
            details: Details of the compliance check
            metadata: Additional compliance metadata
            
        Returns:
            True if successful, False otherwise
        """
        payload = {
            'type': 'compliance',
            'data': {
                'agent_id': self.agent_id,
                'compliance_type': compliance_type,
                'status': status,
                'details': details,
                'metadata': metadata
            }
        }
        
        return self._send_request('/api/agents/log', payload)
    
    def analyze_request_security(self, request_data: str) -> Dict[str, Any]:
        """
        Analyze request data for security threats.
        
        Args:
            request_data: The request data to analyze
            
        Returns:
            Dictionary containing security analysis results
        """
        return self.security.analyze_request_security("user_input", {
            'content': request_data
        })
    
    def check_data_privacy(self, text: str) -> Dict[str, Any]:
        """
        Check text for PII and privacy concerns.
        
        Args:
            text: Text to analyze for PII
            
        Returns:
            Dictionary containing privacy analysis results
        """
        return self.security.check_data_privacy(text)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all collected metrics.
        
        Returns:
            Dictionary containing metrics summary
        """
        return {
            'metrics': self.metrics.get_summary(),
            'health': self.health.get_health_summary(),
            'security': self.security.get_security_summary()
        }
    
    def _send_request(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """
        Send a request to the backend API.
        
        Args:
            endpoint: API endpoint path
            data: Request payload
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Use mock endpoints if available
            if endpoint.startswith('/api/agents/'):
                endpoint = endpoint.replace('/api/agents/', '/api/mock/')
            
            url = f"{self.backend_url}{endpoint}"
            response = requests.post(
                url,
                json=data,
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code in [200, 201]:
                return True
            else:
                print(f"API request failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error: {e}")
            return False 