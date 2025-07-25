#!/usr/bin/env python3
"""
Sample AI Agent for testing HR Agent Operations Platform
This demonstrates how to integrate the HR Agent SDK into your AI agents
"""

import time
import random
import openai
from hr_agent_sdk import AgentTracker

# Initialize the tracker
# Replace with your actual agent ID and API key
tracker = AgentTracker(
    agent_id="550e8400-e29b-41d4-a716-446655440000",  # Example UUID
    api_key="your-api-key-here",
    base_url="https://hr-agent-backend-1080649900100.me-central1.run.app/api"
)

def simulate_openai_request():
    """Simulate an OpenAI API call with tracking"""
    
    # Sample user input
    user_input = "What is the capital of France?"
    
    # Analyze security before processing
    security_analysis = tracker.analyze_request_security(
        request_data=f"User query: {user_input}",
        user_input=user_input
    )
    
    print(f"Security analysis: {security_analysis}")
    
    # Log security event if threat detected
    if security_analysis['threat_level'] > 30:
        tracker.log_security_event(
            event_type="suspicious_activity",
            description=f"Elevated threat level: {security_analysis['threat_level']}",
            severity=security_analysis['severity'],
            threat_level=security_analysis['threat_level'],
            metadata={"threats": security_analysis['threats']}
        )
    
    # Check for privacy concerns
    privacy_check = tracker.check_data_privacy(user_input)
    if privacy_check['has_pii']:
        tracker.log_compliance_event(
            compliance_type="gdpr",
            event_description="PII detected in user input",
            data_processed=privacy_check['findings'],
            user_consent=True,  # Assume consent was given
            encryption_status=True
        )
    
    # Track the AI request
    with tracker.track_request("chat_completion") as context:
        # Simulate API call delay
        time.sleep(random.uniform(0.5, 2.0))
        
        # Simulate response (replace with actual OpenAI call)
        # response = openai.ChatCompletion.create(...)
        
        # Simulate token usage and cost
        prompt_tokens = random.randint(10, 100)
        completion_tokens = random.randint(20, 200)
        cost = (prompt_tokens * 0.03 + completion_tokens * 0.06) / 1000  # GPT-4 pricing
        
        # Update tracking context
        context["prompt_tokens"] = prompt_tokens
        context["completion_tokens"] = completion_tokens
        context["cost"] = cost
        context["model"] = "gpt-4"
        context["provider"] = "openai"
        
        print(f"Simulated response: The capital of France is Paris.")
        print(f"Tokens used: {prompt_tokens + completion_tokens}, Cost: ${cost:.4f}")

def simulate_error():
    """Simulate an error scenario"""
    try:
        # Simulate an error
        raise Exception("Simulated API timeout error")
    except Exception as e:
        tracker.log_error(
            error_message=str(e),
            latency=3.0,
            operation="chat_completion"
        )
        print(f"Error logged: {e}")

def simulate_health_check():
    """Simulate health monitoring"""
    # Random health status
    statuses = ["healthy", "degraded", "healthy", "healthy"]  # Mostly healthy
    status = random.choice(statuses)
    
    tracker.log_health(
        status=status,
        memory_usage=random.uniform(100, 500),  # MB
        cpu_usage=random.uniform(10, 80)  # %
    )
    
    print(f"Health status: {status}")

def main():
    """Main demo function"""
    print("🤖 Starting AI Agent with HR Operations Platform tracking...")
    print(f"Agent ID: {tracker.agent_id}")
    print("-" * 60)
    
    # Simulate multiple requests
    for i in range(5):
        print(f"\n📊 Request {i+1}/5:")
        
        # 80% normal requests, 20% with errors
        if random.random() < 0.8:
            simulate_openai_request()
        else:
            simulate_error()
        
        # Health check every 2 requests
        if i % 2 == 0:
            simulate_health_check()
        
        # Wait between requests
        time.sleep(1)
    
    # Security event simulation
    print(f"\n🔒 Simulating security events...")
    tracker.log_security_event(
        event_type="rate_limit_exceeded",
        description="Multiple rapid requests detected",
        severity="medium",
        source_ip="192.168.1.100",
        endpoint="/api/chat",
        blocked=False
    )
    
    # Compliance logging
    print(f"\n📋 Logging compliance events...")
    tracker.log_compliance_event(
        compliance_type="gdpr",
        event_description="User data processed for chat completion",
        data_processed={"user_input": "masked_content"},
        user_consent=True,
        encryption_status=True,
        data_location="eu-west-1"
    )
    
    # Get final metrics summary
    print(f"\n📈 Final Metrics Summary:")
    summary = tracker.get_metrics_summary()
    for key, value in summary.items():
        if key != 'security':
            print(f"  {key}: {value}")
    
    print(f"\n🔐 Security Summary:")
    for key, value in summary['security'].items():
        print(f"  {key}: {value}")
    
    print(f"\n✅ Demo completed! Check your HR Agent Operations Platform dashboard.")

if __name__ == "__main__":
    main() 