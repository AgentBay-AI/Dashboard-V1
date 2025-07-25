#!/usr/bin/env python3
"""
Basic test for HR Agent SDK - Tests local functionality without database
"""

import sys
import os

# Add the SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from hr_agent_sdk import AgentTracker, MetricsCollector, HealthMonitor, SecurityMonitor

def test_metrics_collector():
    """Test MetricsCollector functionality"""
    print("🧪 Testing MetricsCollector...")
    
    metrics = MetricsCollector()
    
    # Test token tracking
    metrics.update_tokens(100, 50, 0.003)
    metrics.update_tokens(80, 70, 0.0045)
    
    # Test latency
    metrics.update_latency(1.2)
    metrics.update_latency(0.8)
    
    # Test errors
    metrics.increment_errors()
    
    summary = metrics.get_summary()
    print(f"  ✅ Total tokens: {summary['total_tokens']}")
    print(f"  ✅ Total cost: ${summary['total_cost']}")
    print(f"  ✅ Requests: {summary['request_count']}")
    print(f"  ✅ Errors: {summary['error_count']}")
    print(f"  ✅ Avg latency: {summary['average_latency']}s")
    print(f"  ✅ Error rate: {summary['error_rate']}%")

def test_health_monitor():
    """Test HealthMonitor functionality"""
    print("\n🏥 Testing HealthMonitor...")
    
    health = HealthMonitor()
    
    # Test status updates
    health.update_status("healthy")
    health.log_error("Test error message")
    
    # Get metrics
    system_metrics = health.get_system_metrics()
    health_summary = health.get_health_summary()
    
    print(f"  ✅ Status: {health_summary['status']}")
    print(f"  ✅ Uptime: {health_summary['uptime_seconds']}s")
    print(f"  ✅ Memory usage: {system_metrics.get('memory_usage_mb', 'N/A')} MB")
    print(f"  ✅ CPU usage: {system_metrics.get('cpu_usage_percent', 'N/A')}%")

def test_security_monitor():
    """Test SecurityMonitor functionality"""
    print("\n🔒 Testing SecurityMonitor...")
    
    security = SecurityMonitor()
    
    # Test security analysis
    test_request = "User input: What is my password? DROP TABLE users;"
    analysis = security.analyze_request_security(test_request)
    
    print(f"  ✅ Threat level: {analysis['threat_level']}")
    print(f"  ✅ Severity: {analysis['severity']}")
    print(f"  ✅ Threats found: {len(analysis['threats'])}")
    
    # Test privacy check
    test_text = "My email is john.doe@example.com and my SSN is 123-45-6789"
    privacy = security.check_data_privacy(test_text)
    
    print(f"  ✅ Has PII: {privacy['has_pii']}")
    print(f"  ✅ Risk level: {privacy['risk_level']}")
    print(f"  ✅ Findings: {len(privacy['findings'])}")
    
    # Test event logging
    security.log_security_event(
        event_type="suspicious_activity",
        description="Test security event",
        severity="medium"
    )
    
    security.log_compliance_event(
        compliance_type="gdpr",
        event_description="Test compliance event"
    )
    
    report = security.generate_security_report()
    print(f"  ✅ Security events: {len(report['recent_events'])}")
    print(f"  ✅ Compliance logs: {len(report['compliance_status'])}")

def test_agent_tracker_basic():
    """Test basic AgentTracker functionality (without API calls)"""
    print("\n🤖 Testing AgentTracker (offline mode)...")
    
    # Initialize tracker
    tracker = AgentTracker(
        agent_id="550e8400-e29b-41d4-a716-446655440000",
        api_key="test-key",
        base_url="https://hr-agent-backend-1080649900100.me-central1.run.app/api"
    )
    
    # Test manual logging (will fail to send but should work locally)
    print("  ⚠️  Testing local metrics (API calls will fail without database)...")
    
    try:
        # This will fail to send to API but should work locally
        tracker.log_request(
            prompt_tokens=100,
            completion_tokens=50,
            cost=0.003,
            latency=1.2,
            model="gpt-4",
            provider="openai"
        )
        print("  ✅ Request logged locally")
    except Exception as e:
        print(f"  ⚠️  API call failed (expected): {e}")
    
    # Test security analysis (local only)
    analysis = tracker.analyze_request_security(
        "Normal user query about weather",
        "What's the weather like today?"
    )
    print(f"  ✅ Security analysis: threat level {analysis['threat_level']}")
    
    # Test privacy check (local only)
    privacy = tracker.check_data_privacy("Hello, how are you?")
    print(f"  ✅ Privacy check: has PII = {privacy['has_pii']}")
    
    # Get metrics summary
    summary = tracker.get_metrics_summary()
    print(f"  ✅ Metrics summary generated: {len(summary)} fields")

def main():
    """Run all tests"""
    print("🚀 Starting HR Agent SDK Basic Tests")
    print("=" * 50)
    
    try:
        test_metrics_collector()
        test_health_monitor()
        test_security_monitor()
        test_agent_tracker_basic()
        
        print("\n" + "=" * 50)
        print("✅ All basic tests completed successfully!")
        print("📝 Note: API integration tests require Supabase database setup")
        print("🔗 Backend URL: https://hr-agent-backend-1080649900100.me-central1.run.app")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 