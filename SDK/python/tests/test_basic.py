#!/usr/bin/env python3
"""
Basic tests for HR Agent SDK components.

These tests verify the core functionality of the SDK without
making actual API calls to the backend.
"""

import time
import uuid
import pytest
from unittest.mock import patch, MagicMock

# Import SDK components
from hr_agent_sdk import AgentTracker, MetricsCollector, HealthMonitor, SecurityMonitor


class TestMetricsCollector:
    """Test the MetricsCollector class."""
    
    def test_initialization(self):
        """Test metrics collector initialization."""
        metrics = MetricsCollector()
        assert metrics.total_tokens == 0
        assert metrics.total_cost == 0.0
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
    
    def test_update_tokens(self):
        """Test token and cost tracking."""
        metrics = MetricsCollector()
        
        metrics.update_tokens(100, 0.002)
        assert metrics.total_tokens == 100
        assert metrics.total_cost == 0.002
        
        metrics.update_tokens(50, 0.001)
        assert metrics.total_tokens == 150
        assert metrics.total_cost == 0.003
    
    def test_update_request(self):
        """Test request tracking."""
        metrics = MetricsCollector()
        
        # Successful request
        metrics.update_request(250.0, success=True)
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 1
        assert metrics.failed_requests == 0
        assert len(metrics.latencies) == 1
        assert metrics.latencies[0] == 250.0
        
        # Failed request
        metrics.update_request(500.0, success=False)
        assert metrics.total_requests == 2
        assert metrics.successful_requests == 1
        assert metrics.failed_requests == 1
    
    def test_success_rate(self):
        """Test success rate calculation."""
        metrics = MetricsCollector()
        
        # No requests = 100% success rate
        assert metrics.get_success_rate() == 100.0
        
        # 3 successful, 1 failed = 75% success rate
        for _ in range(3):
            metrics.update_request(100.0, success=True)
        metrics.update_request(100.0, success=False)
        
        assert metrics.get_success_rate() == 75.0
    
    def test_average_latency(self):
        """Test average latency calculation."""
        metrics = MetricsCollector()
        
        # No requests = 0 latency
        assert metrics.get_average_latency() == 0.0
        
        # Test with actual latencies
        latencies = [100.0, 200.0, 300.0]
        for latency in latencies:
            metrics.update_request(latency, success=True)
        
        expected_avg = sum(latencies) / len(latencies)
        assert metrics.get_average_latency() == expected_avg
    
    def test_error_tracking(self):
        """Test error tracking."""
        metrics = MetricsCollector()
        
        metrics.update_error("APIError")
        metrics.update_error("APIError")
        metrics.update_error("NetworkError")
        
        assert metrics.errors["APIError"] == 2
        assert metrics.errors["NetworkError"] == 1
    
    def test_get_summary(self):
        """Test metrics summary generation."""
        metrics = MetricsCollector()
        
        # Add some test data
        metrics.update_tokens(100, 0.002)
        metrics.update_request(250.0, success=True)
        metrics.update_request(150.0, success=False)
        metrics.update_error("TestError")
        
        summary = metrics.get_summary()
        
        assert isinstance(summary, dict)
        assert summary['total_tokens'] == 100
        assert summary['total_cost'] == 0.002
        assert summary['total_requests'] == 2
        assert summary['successful_requests'] == 1
        assert summary['failed_requests'] == 1
        assert summary['success_rate'] == 50.0
        assert 'average_latency' in summary
        assert 'error_breakdown' in summary


class TestHealthMonitor:
    """Test the HealthMonitor class."""
    
    def test_initialization(self):
        """Test health monitor initialization."""
        health = HealthMonitor()
        assert health.status == "healthy"
        assert health.error_count == 0
        assert health.total_checks == 0
    
    def test_update_status(self):
        """Test status updates."""
        health = HealthMonitor()
        
        # Valid status updates
        for status in ["healthy", "warning", "critical"]:
            health.update_status(status)
            assert health.status == status
        
        # Invalid status should raise ValueError
        with pytest.raises(ValueError):
            health.update_status("invalid_status")
    
    def test_uptime_calculation(self):
        """Test uptime calculation."""
        health = HealthMonitor()
        
        # Should be close to 0 when just created
        uptime = health.get_uptime()
        assert 0 <= uptime < 0.1  # Less than 0.1 hours (6 minutes)
        
        # Test with mocked start time
        past_time = time.time() - 3600  # 1 hour ago
        health.start_time = past_time
        uptime = health.get_uptime()
        assert 0.9 < uptime < 1.1  # Approximately 1 hour
    
    def test_response_time_logging(self):
        """Test response time logging."""
        health = HealthMonitor()
        
        health.log_response_time(100.0)
        health.log_response_time(200.0)
        health.log_response_time(150.0)
        
        assert len(health.response_times) == 3
        assert health.max_response_time == 200.0
        assert health.get_average_response_time() == 150.0
    
    def test_error_logging(self):
        """Test error logging."""
        health = HealthMonitor()
        
        # Log some errors
        for _ in range(3):
            health.log_error("TestError")
        
        assert health.error_count == 3
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    @patch('psutil.net_io_counters')
    @patch('psutil.Process')
    def test_system_metrics(self, mock_process, mock_net, mock_disk, mock_memory, mock_cpu):
        """Test system metrics collection."""
        # Mock psutil responses
        mock_cpu.return_value = 45.0
        mock_memory.return_value = MagicMock(percent=60.0, available=8*1024**3, total=16*1024**3)
        mock_disk.return_value = MagicMock(percent=75.0, free=100*1024**3, total=500*1024**3)
        mock_net.return_value = MagicMock(bytes_sent=1000, bytes_recv=2000)
        
        mock_process_instance = MagicMock()
        mock_process_instance.memory_info.return_value = MagicMock(rss=100*1024**2)  # 100MB
        mock_process_instance.cpu_percent.return_value = 15.0
        mock_process.return_value = mock_process_instance
        
        health = HealthMonitor()
        metrics = health.get_system_metrics()
        
        assert isinstance(metrics, dict)
        assert metrics['cpu_percent'] == 45.0
        assert metrics['memory_percent'] == 60.0
        assert 'memory_available_gb' in metrics
        assert 'disk_percent' in metrics
        assert 'process_memory_mb' in metrics
    
    def test_health_summary(self):
        """Test health summary generation."""
        health = HealthMonitor()
        
        # Add some test data
        health.log_response_time(100.0)
        health.log_error("TestError")
        health.update_status("warning")
        
        summary = health.get_health_summary()
        
        assert isinstance(summary, dict)
        assert summary['status'] == "warning"
        assert summary['error_count'] == 1
        assert 'uptime_hours' in summary
        assert 'system_metrics' in summary


class TestSecurityMonitor:
    """Test the SecurityMonitor class."""
    
    def test_initialization(self):
        """Test security monitor initialization."""
        security = SecurityMonitor()
        assert len(security.security_events) == 0
        assert len(security.compliance_logs) == 0
        assert isinstance(security.threat_patterns, dict)
        assert isinstance(security.pii_patterns, dict)
    
    def test_sql_injection_detection(self):
        """Test SQL injection threat detection."""
        security = SecurityMonitor()
        
        # Safe input
        safe_input = "What is the weather today?"
        result = security.analyze_request_security("test", {"content": safe_input})
        assert result['safe'] == True
        assert result['threat_count'] == 0
        
        # SQL injection attempt
        malicious_input = "SELECT * FROM users; DROP TABLE users;"
        result = security.analyze_request_security("test", {"content": malicious_input})
        assert result['safe'] == False
        assert result['threat_count'] > 0
        assert any(threat['type'] == 'sql_injection' for threat in result['threats_detected'])
    
    def test_xss_detection(self):
        """Test XSS threat detection."""
        security = SecurityMonitor()
        
        # XSS attempt
        xss_input = '<script>alert("xss")</script>'
        result = security.analyze_request_security("test", {"content": xss_input})
        assert result['safe'] == False
        assert any(threat['type'] == 'xss' for threat in result['threats_detected'])
    
    def test_pii_detection(self):
        """Test PII detection."""
        security = SecurityMonitor()
        
        # Text without PII
        safe_text = "Hello, how are you today?"
        result = security.check_data_privacy(safe_text)
        assert result['privacy_safe'] == True
        assert result['pii_types_count'] == 0
        
        # Text with email
        email_text = "Contact me at john.doe@example.com"
        result = security.check_data_privacy(email_text)
        assert result['privacy_safe'] == False
        assert result['pii_types_count'] > 0
        assert any(pii['type'] == 'email' for pii in result['pii_detected'])
        
        # Text with phone number
        phone_text = "Call me at 555-123-4567"
        result = security.check_data_privacy(phone_text)
        assert result['privacy_safe'] == False
        assert any(pii['type'] == 'phone' for pii in result['pii_detected'])
    
    def test_security_event_logging(self):
        """Test security event logging."""
        security = SecurityMonitor()
        
        security.log_security_event(
            event_type="test_event",
            description="Test security event",
            severity="medium"
        )
        
        assert len(security.security_events) == 1
        event = security.security_events[0]
        assert event['event_type'] == "test_event"
        assert event['severity'] == "medium"
        assert 'timestamp' in event
    
    def test_compliance_event_logging(self):
        """Test compliance event logging."""
        security = SecurityMonitor()
        
        security.log_compliance_event(
            compliance_type="pii_check",
            status="compliant",
            details="No PII detected"
        )
        
        assert len(security.compliance_logs) == 1
        log = security.compliance_logs[0]
        assert log['compliance_type'] == "pii_check"
        assert log['status'] == "compliant"
        assert 'timestamp' in log
    
    def test_security_summary(self):
        """Test security summary generation."""
        security = SecurityMonitor()
        
        # Add some test data
        security.log_security_event("test_event", "Test", "high")
        security.log_compliance_event("test_compliance", "compliant", "Test")
        
        summary = security.get_security_summary()
        
        assert isinstance(summary, dict)
        assert summary['total_security_events'] == 1
        assert summary['total_compliance_logs'] == 1
        assert 'security_score' in summary
        assert 'compliance_score' in summary


class TestAgentTracker:
    """Test the AgentTracker class."""
    
    @patch('requests.post')
    def test_initialization(self, mock_post):
        """Test agent tracker initialization."""
        agent_id = str(uuid.uuid4())
        tracker = AgentTracker(
            agent_id=agent_id,
            backend_url="http://localhost:8080"
        )
        
        assert tracker.agent_id == agent_id
        assert tracker.backend_url == "http://localhost:8080"
        assert isinstance(tracker.metrics, MetricsCollector)
        assert isinstance(tracker.health, HealthMonitor)
        assert isinstance(tracker.security, SecurityMonitor)
    
    @patch('requests.post')
    def test_log_tokens(self, mock_post):
        """Test token logging."""
        mock_post.return_value.status_code = 201
        
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        result = tracker.log_tokens(
            input_tokens=100,
            output_tokens=50,
            cost=0.002
        )
        
        assert result == True
        assert mock_post.called
        
        # Check call arguments
        call_args = mock_post.call_args
        assert call_args[0][0].endswith('/api/agents/log')
        assert 'json' in call_args[1]
        
        json_data = call_args[1]['json']
        assert json_data['type'] == 'metrics'
        assert json_data['data']['total_tokens'] == 150
        assert json_data['data']['input_tokens'] == 100
        assert json_data['data']['output_tokens'] == 50
    
    @patch('requests.post')
    def test_log_error(self, mock_post):
        """Test error logging."""
        mock_post.return_value.status_code = 201
        
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        result = tracker.log_error(
            error_type="TestError",
            error_message="Test error message",
            severity="high"
        )
        
        assert result == True
        assert mock_post.called
        
        json_data = mock_post.call_args[1]['json']
        assert json_data['type'] == 'error'
        assert json_data['data']['error_type'] == "TestError"
        assert json_data['data']['severity'] == "high"
    
    @patch('requests.post')
    def test_log_health(self, mock_post):
        """Test health logging."""
        mock_post.return_value.status_code = 201
        
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        result = tracker.log_health(status="healthy")
        
        assert result == True
        assert mock_post.called
        
        json_data = mock_post.call_args[1]['json']
        assert json_data['agent_id'] == tracker.agent_id
        assert json_data['status'] == "healthy"
    
    def test_track_request_context_manager(self):
        """Test the track_request context manager."""
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        # Test successful operation
        with tracker.track_request("test_operation") as request_id:
            assert isinstance(request_id, str)
            time.sleep(0.1)  # Simulate some work
        
        # Check that metrics were updated
        assert tracker.metrics.total_requests == 1
        assert tracker.metrics.successful_requests == 1
        assert len(tracker.metrics.latencies) == 1
        assert tracker.metrics.latencies[0] > 0  # Should have some latency
    
    def test_track_request_with_exception(self):
        """Test the track_request context manager with exceptions."""
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        # Test operation that raises an exception
        with pytest.raises(ValueError):
            with tracker.track_request("test_operation"):
                raise ValueError("Test exception")
        
        # Check that metrics were updated for failed request
        assert tracker.metrics.total_requests == 1
        assert tracker.metrics.failed_requests == 1
        assert tracker.metrics.errors["ValueError"] == 1
    
    def test_get_metrics_summary(self):
        """Test metrics summary generation."""
        tracker = AgentTracker(
            agent_id=str(uuid.uuid4()),
            backend_url="http://localhost:8080"
        )
        
        # Add some test data
        tracker.metrics.update_tokens(100, 0.002)
        tracker.health.log_response_time(150.0)
        tracker.security.log_security_event("test", "Test event", "low")
        
        summary = tracker.get_metrics_summary()
        
        assert isinstance(summary, dict)
        assert 'metrics' in summary
        assert 'health' in summary
        assert 'security' in summary


if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"]) 