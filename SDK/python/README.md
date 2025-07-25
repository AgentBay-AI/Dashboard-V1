# HR Agent SDK - Python

A comprehensive Python SDK for the AI Agent Operations Platform. Track performance, health, costs, security events, and compliance for your AI agents.

## 🚀 Features

- **Performance Tracking**: Monitor token usage, costs, latency, and success rates
- **Health Monitoring**: Track system resources, uptime, and agent health status
- **Security Analysis**: Detect threats like SQL injection, XSS, and command injection
- **Privacy Protection**: Automatically detect PII and ensure compliance
- **Real-time Logging**: Send metrics to your backend dashboard in real-time
- **Context Managers**: Easy integration with automatic request tracking

## 📦 Installation

### From PyPI (Coming Soon)
```bash
pip install hr-agent-sdk
```

### From Source
```bash
git clone https://github.com/your-repo/ai-hr-agent.git
cd ai-hr-agent/SDK/python
pip install -e .
```

### Dependencies
```bash
pip install requests psutil typing-extensions
```

## 🏃 Quick Start

```python
from hr_agent_sdk import AgentTracker
import uuid

# Initialize the tracker
tracker = AgentTracker(
    agent_id=str(uuid.uuid4()),
    backend_url="https://your-backend.run.app",
    api_key="your-api-key"  # Optional for development
)

# Track an AI operation
with tracker.track_request("openai_completion") as request_id:
    # Your AI operation here
    response = openai.Completion.create(
        engine="gpt-3.5-turbo",
        prompt="Hello, world!",
        max_tokens=100
    )
    
    # Log token usage and cost
    tracker.log_tokens(
        input_tokens=50,
        output_tokens=100,
        cost=0.002
    )

# Log health status
tracker.log_health(status="healthy")

# Check for security threats
security_check = tracker.analyze_request_security("SELECT * FROM users")
if not security_check['safe']:
    print(f"⚠️ Security threat detected: {security_check['threats_detected']}")

# Check for PII
privacy_check = tracker.check_data_privacy("My email is john@example.com")
if not privacy_check['privacy_safe']:
    print(f"🔒 PII detected: {privacy_check['pii_detected']}")
```

## 📊 Complete Example

```python
import time
import uuid
from hr_agent_sdk import AgentTracker

def my_ai_agent():
    # Initialize tracker
    tracker = AgentTracker(
        agent_id=str(uuid.uuid4()),
        backend_url="http://localhost:8080"
    )
    
    try:
        # Process user input
        user_input = "What is machine learning?"
        
        # Check for security threats
        security_analysis = tracker.analyze_request_security(user_input)
        if not security_analysis['safe']:
            tracker.log_security_event(
                event_type='threat_detected',
                description=f"Unsafe input: {security_analysis['threat_count']} threats",
                severity=security_analysis['severity']
            )
            return
        
        # Check for PII
        privacy_check = tracker.check_data_privacy(user_input)
        if privacy_check['pii_types_count'] > 0:
            tracker.log_compliance_event(
                compliance_type='pii_detection',
                status=privacy_check['compliance_status'],
                details=f"PII found: {privacy_check['pii_types_count']} types"
            )
        
        # Process with tracking
        with tracker.track_request("ai_processing") as request_id:
            # Your AI processing here
            time.sleep(1)  # Simulate processing
            
            # Log results
            tracker.log_tokens(
                input_tokens=len(user_input.split()) * 1.3,
                output_tokens=150,
                cost=0.003
            )
        
        # Log successful health
        tracker.log_health(status="healthy")
        
    except Exception as e:
        # Log errors automatically
        tracker.log_error(
            error_type=type(e).__name__,
            error_message=str(e),
            severity="high"
        )
        
        # Log unhealthy status
        tracker.log_health(status="critical")

if __name__ == "__main__":
    my_ai_agent()
```

## 🔧 API Reference

### AgentTracker

Main class for tracking AI agent operations.

#### Constructor

```python
AgentTracker(
    agent_id: str,
    backend_url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
    timeout: int = 30
)
```

#### Methods

##### Context Manager
```python
with tracker.track_request(operation: str = "unknown") as request_id:
    # Your operation here
    pass
```

##### Logging Methods
```python
# Log token usage and costs
tracker.log_tokens(input_tokens: int, output_tokens: int, cost: float = 0.0)

# Log errors
tracker.log_error(
    error_type: str,
    error_message: str,
    stack_trace: Optional[str] = None,
    context: Optional[Dict] = None,
    severity: str = "medium"
)

# Log health status
tracker.log_health(status: str = "healthy", **kwargs)

# Log security events
tracker.log_security_event(
    event_type: str,
    description: str,
    severity: str = "medium",
    metadata: Optional[Dict] = None
)

# Log compliance events
tracker.log_compliance_event(
    compliance_type: str,
    status: str,
    details: str,
    metadata: Optional[Dict] = None
)
```

##### Analysis Methods
```python
# Analyze for security threats
security_result = tracker.analyze_request_security(request_data: str)

# Check for PII
privacy_result = tracker.check_data_privacy(text: str)

# Get metrics summary
summary = tracker.get_metrics_summary()
```

### MetricsCollector

Local metrics aggregation and calculation.

```python
from hr_agent_sdk import MetricsCollector

metrics = MetricsCollector()
metrics.update_tokens(tokens=100, cost=0.002)
metrics.update_request(latency=250.0, success=True)
summary = metrics.get_summary()
```

### HealthMonitor

System health and resource monitoring.

```python
from hr_agent_sdk import HealthMonitor

health = HealthMonitor()
health.perform_health_check()
system_metrics = health.get_system_metrics()
```

### SecurityMonitor

Security threat detection and compliance monitoring.

```python
from hr_agent_sdk import SecurityMonitor

security = SecurityMonitor()
threats = security.analyze_request_security("operation", {"content": "user input"})
pii_check = security.check_data_privacy("sensitive text")
```

## 🔒 Security Features

### Threat Detection
- **SQL Injection**: Detects malicious SQL patterns
- **XSS Attacks**: Identifies cross-site scripting attempts  
- **Command Injection**: Finds command execution attempts
- **Path Traversal**: Catches directory traversal attacks

### PII Detection
- **Email Addresses**: Identifies email patterns
- **Phone Numbers**: Detects phone number formats
- **SSN**: Finds Social Security Numbers
- **Credit Cards**: Identifies credit card patterns
- **IP Addresses**: Detects IP address patterns

## 📈 Metrics Tracked

### Performance Metrics
- Total requests processed
- Success/failure rates
- Average response latency
- Token usage (input/output)
- Cost tracking per operation

### Health Metrics
- System uptime
- CPU and memory usage
- Disk usage
- Network I/O
- Error rates
- Response times

### Security Metrics
- Threat detection events
- Security score (0-100)
- Compliance violations
- PII exposure incidents

## 🔗 Integration Examples

### OpenAI Integration
```python
import openai
from hr_agent_sdk import AgentTracker

tracker = AgentTracker(agent_id="openai-agent")

def chat_completion(prompt):
    with tracker.track_request("openai_chat") as request_id:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Log usage
        tracker.log_tokens(
            input_tokens=response['usage']['prompt_tokens'],
            output_tokens=response['usage']['completion_tokens'],
            cost=calculate_cost(response['usage'])
        )
        
        return response
```

### LangChain Integration
```python
from langchain.llms import OpenAI
from hr_agent_sdk import AgentTracker

class TrackedLLM(OpenAI):
    def __init__(self, tracker: AgentTracker, **kwargs):
        super().__init__(**kwargs)
        self.tracker = tracker
    
    def _call(self, prompt: str, stop=None):
        with self.tracker.track_request("langchain_call"):
            # Security check
            security_check = self.tracker.analyze_request_security(prompt)
            if not security_check['safe']:
                raise ValueError("Unsafe prompt detected")
            
            result = super()._call(prompt, stop)
            
            # Log metrics (you'd extract real token counts from the LLM)
            self.tracker.log_tokens(
                input_tokens=len(prompt.split()) * 1.3,
                output_tokens=len(result.split()) * 1.3,
                cost=0.002
            )
            
            return result
```

## 🚀 Deployment

### Environment Variables
```bash
export HR_AGENT_BACKEND_URL="https://your-backend.run.app"
export HR_AGENT_API_KEY="your-api-key"
export HR_AGENT_ID="your-agent-id"
```

### Docker Integration
```dockerfile
FROM python:3.9

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["python", "your_agent.py"]
```

## 🧪 Testing

Run the included test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# Run with coverage
pytest --cov=hr_agent_sdk tests/
```

Run the sample agent:

```bash
cd examples/
python sample_agent.py
```

## 📝 Configuration

### Backend Configuration
Set up your backend URL and credentials:

```python
tracker = AgentTracker(
    agent_id="your-agent-id",
    backend_url="https://your-backend.run.app",
    api_key="your-api-key",
    timeout=30
)
```

### Logging Configuration
The SDK uses Python's logging module. Configure as needed:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Documentation](https://docs.ai-hr-agent.com)
- [Dashboard](https://dashboard.ai-hr-agent.com)
- [GitHub Repository](https://github.com/your-repo/ai-hr-agent)
- [Issue Tracker](https://github.com/your-repo/ai-hr-agent/issues)

## 🆘 Support

- 📧 Email: support@ai-hr-agent.com
- 💬 Discord: [Join our community](https://discord.gg/ai-hr-agent)
- 📖 Documentation: [Read the docs](https://docs.ai-hr-agent.com)

---

**Made with ❤️ by the AI-HR-Agent Team** 