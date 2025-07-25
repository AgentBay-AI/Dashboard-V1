# HR Agent SDK - Python

Track performance, health, and cost metrics for your AI agents in real-time.

## Installation

```bash
pip install hr-agent-sdk
```

## Quick Start

```python
from hr_agent_sdk import AgentTracker

# Initialize tracker
tracker = AgentTracker(
    agent_id="your-agent-uuid",
    api_key="your-api-key"
)

# Track AI requests automatically
with tracker.track_request("chat_completion") as context:
    # Your AI request here
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}]
    )
    
    # Update context with usage data
    context["prompt_tokens"] = response.usage.prompt_tokens
    context["completion_tokens"] = response.usage.completion_tokens
    context["cost"] = 0.002  # Calculate based on your pricing
    context["model"] = "gpt-4"
    context["provider"] = "openai"

# Manual logging
tracker.log_request(
    prompt_tokens=100,
    completion_tokens=50,
    cost=0.003,
    latency=1.5,
    model="gpt-4",
    provider="openai"
)

# Log health status
tracker.log_health(
    status="healthy",
    memory_usage=256.0,  # MB
    cpu_usage=15.2      # %
)

# Get metrics summary
summary = tracker.get_metrics_summary()
print(summary)
```

## Features

- **Automatic Request Tracking**: Context manager for seamless integration
- **Health Monitoring**: System metrics and uptime tracking
- **Error Logging**: Automatic error capture and reporting
- **Cost Tracking**: Monitor AI API costs in real-time
- **Performance Metrics**: Latency and throughput monitoring
- **Multi-Provider Support**: OpenAI, Anthropic, and custom endpoints

## API Reference

### AgentTracker

Main class for tracking agent metrics.

#### Methods

- `track_request(operation_name)`: Context manager for automatic tracking
- `log_request(prompt_tokens, completion_tokens, cost, latency, ...)`: Manual request logging
- `log_health(status, memory_usage, cpu_usage)`: Log health status
- `log_error(error_message, latency, operation)`: Log errors
- `get_metrics_summary()`: Get current metrics summary

### Configuration

Set the base URL for your HR Agent Platform:

```python
tracker = AgentTracker(
    agent_id="your-agent-uuid",
    api_key="your-api-key",
    base_url="https://your-platform.com/api"  # Optional
)
```

## Dashboard Integration

This SDK automatically sends data to your HR Agent Operations Platform dashboard where you can:

- View real-time agent performance
- Monitor costs and usage patterns
- Set up alerts for errors or anomalies
- Analyze trends over time

## Support

- Documentation: [docs.hr-agent.com](https://docs.hr-agent.com)
- Issues: [GitHub Issues](https://github.com/your-org/ai-hr-agent/issues)
- Email: support@hr-agent.com 