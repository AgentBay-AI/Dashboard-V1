#!/usr/bin/env python3
"""
Sample AI Agent using HR Agent SDK with Mock Backend

This example demonstrates the SDK working with mock endpoints.
"""

import time
import random
import uuid
from hr_agent_sdk import AgentTracker


def run_sample_agent_with_mock():
    """Run a sample AI agent with mock backend endpoints."""
    
    # Initialize the agent tracker with mock endpoints
    agent_id = str(uuid.uuid4())
    tracker = AgentTracker(
        agent_id=agent_id,
        backend_url="http://localhost:8080",  # Base backend URL
    )
    
    print(f"🤖 Starting Sample AI Agent with Mock Backend")
    print(f"🆔 Agent ID: {agent_id}")
    print(f"📊 Backend URL: {tracker.backend_url}")
    print("=" * 60)
    
    try:
        # Test logging metrics
        print("\n📊 Testing metrics logging...")
        result = tracker.log_tokens(
            input_tokens=100,
            output_tokens=150,
            cost=0.005
        )
        print(f"✅ Metrics logged: {result}")
        
        # Test logging health
        print("\n💚 Testing health logging...")
        result = tracker.log_health(
            status="healthy",
            response_time=250.5,
            error_rate=2.1
        )
        print(f"✅ Health logged: {result}")
        
        # Test logging error
        print("\n❌ Testing error logging...")
        result = tracker.log_error(
            error_type="TestError",
            error_message="This is a test error for demonstration",
            severity="medium"
        )
        print(f"✅ Error logged: {result}")
        
        # Test logging security event
        print("\n🔒 Testing security event logging...")
        result = tracker.log_security_event(
            event_type="test_security_event",
            description="Test security event for demonstration",
            severity="low"
        )
        print(f"✅ Security event logged: {result}")
        
        # Test logging compliance event
        print("\n📋 Testing compliance event logging...")
        result = tracker.log_compliance_event(
            compliance_type="test_compliance",
            status="compliant",
            details="Test compliance check passed"
        )
        print(f"✅ Compliance event logged: {result}")
        
        # Test context manager
        print("\n🔄 Testing context manager...")
        with tracker.track_request("test_operation") as request_id:
            print(f"📝 Request ID: {request_id}")
            time.sleep(0.5)  # Simulate work
            tracker.log_tokens(50, 75, 0.002)
        print("✅ Context manager test completed")
        
        # Get final metrics summary
        summary = tracker.get_metrics_summary()
        print("\n📈 Final Metrics Summary:")
        print("=" * 40)
        
        metrics = summary['metrics']
        print(f"📊 Total Requests: {metrics['total_requests']}")
        print(f"🎯 Success Rate: {metrics['success_rate']:.1f}%")
        print(f"⚡ Avg Latency: {metrics['average_latency']:.1f}ms")
        print(f"💰 Total Cost: ${metrics['total_cost']:.4f}")
        print(f"🔤 Total Tokens: {metrics['total_tokens']}")
        
        health = summary['health']
        print(f"💚 Health Status: {health['status']}")
        print(f"⏱️  Uptime: {health['uptime_hours']:.2f} hours")
        
        security = summary['security']
        print(f"🔒 Security Score: {security['security_score']:.1f}/100")
        print(f"📋 Compliance Score: {security['compliance_score']:.1f}/100")
        print(f"🚨 Security Events: {security['total_security_events']}")
        
        print("\n✨ Mock sample agent completed successfully!")
        print("📊 Check your dashboard to see the mock data!")
        
    except Exception as e:
        print(f"\n💥 Error: {e}")
        tracker.log_error(
            error_type="UnexpectedError", 
            error_message=str(e),
            severity="high"
        )


if __name__ == "__main__":
    run_sample_agent_with_mock() 