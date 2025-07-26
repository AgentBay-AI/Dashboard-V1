#!/usr/bin/env python3
"""
Quick connection test for HR Agent SDK

This script tests the basic connectivity between the SDK and backend.
"""

import requests
import sys
import json
from datetime import datetime

def test_backend_connection():
    """Test if the backend is running and reachable."""
    backend_url = "http://localhost:8080"
    
    print("🔄 Testing backend connectivity...")
    print(f"Backend URL: {backend_url}")
    
    try:
        # Test health endpoint
        response = requests.get(f"{backend_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend is running and reachable")
            return True
        else:
            print(f"❌ Backend returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend - is it running on port 8080?")
        return False
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return False

def test_database_connection():
    """Test if the backend can connect to the database."""
    backend_url = "http://localhost:8080"
    
    print("\n🔄 Testing database connectivity...")
    
    try:
        # Test frontend organizations endpoint (requires DB)
        response = requests.get(f"{backend_url}/api/frontend/organizations", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ Database connection working")
            print(f"📊 Organizations in DB: {len(data.get('organizations', []))}")
            return True
        else:
            print(f"❌ Database test failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_sdk_import():
    """Test if the SDK can be imported."""
    print("\n🔄 Testing SDK import...")
    
    try:
        from hr_agent_sdk import AgentTracker
        print("✅ SDK imported successfully")
        return True
    except ImportError as e:
        print(f"❌ SDK import failed: {e}")
        print("💡 Run: cd SDK/python && pip install -e .")
        return False

def test_basic_tracking():
    """Test basic SDK tracking functionality."""
    print("\n🔄 Testing basic tracking...")
    
    try:
        from hr_agent_sdk import AgentTracker
        
        # Create a test tracker
        tracker = AgentTracker(
            agent_id="test-agent-connection",
            backend_url="http://localhost:8080"
        )
        
        # Test logging some basic metrics
        print("📊 Logging test metrics...")
        tracker.log_tokens(
            input_tokens=10,
            output_tokens=20,
            cost=0.001
        )
        
        print("💚 Logging test health...")
        tracker.log_health(
            status="healthy",
            response_time=100.0,
            error_rate=0.0
        )
        
        print("✅ Basic tracking test completed")
        return True
        
    except Exception as e:
        print(f"❌ Basic tracking test failed: {e}")
        return False

def main():
    """Run all connection tests."""
    print("🧪 HR Agent SDK Connection Test")
    print("=" * 50)
    
    tests = [
        ("Backend Connection", test_backend_connection),
        ("Database Connection", test_database_connection), 
        ("SDK Import", test_sdk_import),
        ("Basic Tracking", test_basic_tracking)
    ]
    
    results = []
    for test_name, test_func in tests:
        result = test_func()
        results.append((test_name, result))
    
    # Summary
    print("\n" + "=" * 50)
    print("🏁 Test Results Summary:")
    
    all_passed = True
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All tests passed! System is ready for agent tracking.")
        print("\n📖 Next steps:")
        print("1. Create environment files with your API keys")
        print("2. Run: cd SDK/examples && python sample_agent.py")
        print("3. Check your dashboard at http://localhost:3000")
    else:
        print("\n⚠️  Some tests failed. Please fix the issues above.")
        sys.exit(1)

if __name__ == "__main__":
    main() 