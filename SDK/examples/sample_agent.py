#!/usr/bin/env python3
"""
Sample AI Agent using HR Agent SDK

This example demonstrates how to integrate the HR Agent SDK
into your AI agent for comprehensive monitoring and tracking.
"""

import time
import random
import uuid
from hr_agent_sdk import AgentTracker


def simulate_openai_request(prompt: str, tracker: AgentTracker) -> dict:
    """
    Simulate an OpenAI API request with tracking.
    
    Args:
        prompt: The input prompt
        tracker: AgentTracker instance
        
    Returns:
        Simulated response dictionary
    """
    with tracker.track_request("openai_completion") as request_id:
        # Simulate API call delay
        time.sleep(random.uniform(0.5, 2.0))
        
        # Simulate token usage
        input_tokens = len(prompt.split()) * 1.3  # Rough estimate
        output_tokens = random.randint(50, 200)
        
        # Simulate cost calculation (example rates)
        cost = (input_tokens * 0.0015 + output_tokens * 0.002) / 1000
        
        # Log token usage
        tracker.log_tokens(
            input_tokens=int(input_tokens),
            output_tokens=output_tokens,
            cost=cost
        )
        
        # Check for potential security issues
        security_analysis = tracker.analyze_request_security(prompt)
        if not security_analysis['safe']:
            tracker.log_security_event(
                event_type='unsafe_prompt',
                description=f"Potentially unsafe prompt detected: {security_analysis['threat_count']} threats",
                severity=security_analysis['severity']
            )
        
        # Check for PII in the prompt
        privacy_check = tracker.check_data_privacy(prompt)
        if not privacy_check['privacy_safe']:
            tracker.log_compliance_event(
                compliance_type='pii_in_prompt',
                status=privacy_check['compliance_status'],
                details=f"PII detected in prompt: {privacy_check['pii_types_count']} types"
            )
        
        # Simulate response
        response = {
            'id': request_id,
            'content': f"This is a simulated response to: {prompt[:50]}...",
            'tokens_used': input_tokens + output_tokens,
            'cost': cost
        }
        
        return response


def simulate_error_scenario(tracker: AgentTracker):
    """
    Simulate various error scenarios for testing.
    
    Args:
        tracker: AgentTracker instance
    """
    error_types = [
        ("RateLimitError", "API rate limit exceeded", "medium"),
        ("APIError", "OpenAI API returned an error", "high"),
        ("NetworkError", "Network connection failed", "low"),
        ("ValidationError", "Invalid input parameters", "low")
    ]
    
    error_type, message, severity = random.choice(error_types)
    
    tracker.log_error(
        error_type=error_type,
        error_message=message,
        severity=severity,
        context={
            'timestamp': time.time(),
            'simulation': True
        }
    )


def run_sample_agent():
    """
    Run a sample AI agent with comprehensive tracking.
    """
    # Initialize the agent tracker
    agent_id = str(uuid.uuid4())
    tracker = AgentTracker(
        agent_id=agent_id,
        backend_url="http://localhost:8080",  # Change to your backend URL
        # api_key="your-api-key-here"  # Uncomment for production
    )
    
    print(f"🤖 Starting Sample AI Agent (ID: {agent_id})")
    print(f"📊 Backend URL: {tracker.backend_url}")
    print("=" * 60)
    
    # Sample prompts to process
    sample_prompts = [
        "What is the capital of France?",
        "Explain quantum computing in simple terms",
        "Write a short story about a robot",
        "My email is john@example.com and my phone is 555-123-4567",  # Contains PII
        "SELECT * FROM users WHERE id = 1; DROP TABLE users;",  # SQL injection attempt
        "Help me write a professional email",
        "What are the benefits of renewable energy?",
        "Create a marketing plan for a new product"
    ]
    
    try:
        # Process sample requests
        for i, prompt in enumerate(sample_prompts, 1):
            print(f"\n🔄 Processing request {i}/{len(sample_prompts)}")
            print(f"📝 Prompt: {prompt[:50]}...")
            
            try:
                response = simulate_openai_request(prompt, tracker)
                print(f"✅ Response generated (Cost: ${response['cost']:.4f})")
                
                # Randomly simulate some errors
                if random.random() < 0.2:  # 20% chance of error
                    simulate_error_scenario(tracker)
                    print("⚠️  Error logged for testing")
                
            except Exception as e:
                print(f"❌ Error processing request: {e}")
                tracker.log_error(
                    error_type=type(e).__name__,
                    error_message=str(e),
                    severity="high"
                )
            
            # Log health status periodically
            if i % 3 == 0:
                health_status = "healthy" if random.random() > 0.3 else random.choice(["warning", "critical"])
                tracker.log_health(
                    status=health_status,
                    response_time=random.uniform(100, 500),
                    error_rate=random.uniform(0, 10)
                )
                print(f"💚 Health status logged: {health_status}")
            
            # Small delay between requests
            time.sleep(random.uniform(1, 3))
        
        # Final health check
        print("\n🏥 Performing final health check...")
        tracker.log_health(status="healthy")
        
        # Get and display metrics summary
        print("\n📈 Final Metrics Summary:")
        print("=" * 40)
        
        summary = tracker.get_metrics_summary()
        
        # Metrics
        metrics = summary['metrics']
        print(f"📊 Requests: {metrics['total_requests']}")
        print(f"🎯 Success Rate: {metrics['success_rate']:.1f}%")
        print(f"⚡ Avg Latency: {metrics['average_latency']:.1f}ms")
        print(f"💰 Total Cost: ${metrics['total_cost']:.4f}")
        print(f"🔤 Total Tokens: {metrics['total_tokens']}")
        
        # Health
        health = summary['health']
        print(f"💚 Health Status: {health['status']}")
        print(f"⏱️  Uptime: {health['uptime_hours']:.2f} hours")
        print(f"❌ Error Rate: {health['error_rate']:.1f}%")
        
        # Security
        security = summary['security']
        print(f"🔒 Security Score: {security['security_score']:.1f}/100")
        print(f"📋 Compliance Score: {security['compliance_score']:.1f}/100")
        print(f"🚨 Security Events: {security['total_security_events']}")
        
        print("\n✨ Sample agent completed successfully!")
        print("📊 Check your dashboard to see the tracked metrics!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Agent stopped by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        tracker.log_error(
            error_type="UnexpectedError",
            error_message=str(e),
            severity="critical"
        )
    finally:
        # Final health log
        tracker.log_health(status="inactive")
        print(f"👋 Agent {agent_id} shutdown complete")


if __name__ == "__main__":
    run_sample_agent() 