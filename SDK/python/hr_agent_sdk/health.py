import time
import psutil
from typing import Dict, Any, Optional


class HealthMonitor:
    """
    Monitors system health and agent uptime.
    
    This class tracks system resources, uptime, response times,
    and overall health status of the AI agent.
    """
    
    def __init__(self):
        """Initialize the health monitor."""
        self.start_time = time.time()
        self.last_health_check = time.time()
        self.status = "healthy"
        self.error_count = 0
        self.total_checks = 0
        
        # Response time tracking
        self.response_times = []
        self.max_response_time = 0.0
        
        # System metrics
        self.cpu_threshold = 80.0  # Alert if CPU > 80%
        self.memory_threshold = 85.0  # Alert if memory > 85%
        self.disk_threshold = 90.0  # Alert if disk > 90%
    
    def update_status(self, status: str) -> None:
        """
        Update the health status.
        
        Args:
            status: New health status (healthy, warning, critical)
        """
        valid_statuses = ["healthy", "warning", "critical"]
        if status in valid_statuses:
            self.status = status
            self.last_health_check = time.time()
        else:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
    
    def get_uptime(self) -> float:
        """
        Get the uptime in hours.
        
        Returns:
            Uptime in hours since initialization
        """
        uptime_seconds = time.time() - self.start_time
        return uptime_seconds / 3600.0
    
    def log_response_time(self, response_time: float) -> None:
        """
        Log a response time measurement.
        
        Args:
            response_time: Response time in milliseconds
        """
        self.response_times.append(response_time)
        self.max_response_time = max(self.max_response_time, response_time)
        
        # Keep only last 100 measurements for performance
        if len(self.response_times) > 100:
            self.response_times = self.response_times[-100:]
    
    def log_error(self, error_type: str) -> None:
        """
        Log an error occurrence.
        
        Args:
            error_type: Type of error that occurred
        """
        self.error_count += 1
        
        # Update status based on error rate
        error_rate = self.get_error_rate()
        if error_rate > 10:
            self.status = "critical"
        elif error_rate > 5:
            self.status = "warning"
    
    def perform_health_check(self) -> Dict[str, Any]:
        """
        Perform a comprehensive health check.
        
        Returns:
            Dictionary containing health check results
        """
        self.total_checks += 1
        self.last_health_check = time.time()
        
        system_metrics = self.get_system_metrics()
        
        # Determine overall health status
        health_status = "healthy"
        issues = []
        
        # Check CPU usage
        cpu_usage = system_metrics.get('cpu_percent', 0)
        if cpu_usage > self.cpu_threshold:
            health_status = "critical" if cpu_usage > 95 else "warning"
            issues.append(f"High CPU usage: {cpu_usage:.1f}%")
        
        # Check memory usage
        memory_usage = system_metrics.get('memory_percent', 0)
        if memory_usage > self.memory_threshold:
            health_status = "critical" if memory_usage > 95 else "warning"
            issues.append(f"High memory usage: {memory_usage:.1f}%")
        
        # Check disk usage
        disk_usage = system_metrics.get('disk_percent', 0)
        if disk_usage > self.disk_threshold:
            if health_status == "healthy":
                health_status = "warning"
            issues.append(f"High disk usage: {disk_usage:.1f}%")
        
        # Check error rate
        error_rate = self.get_error_rate()
        if error_rate > 10:
            health_status = "critical"
            issues.append(f"High error rate: {error_rate:.1f}%")
        elif error_rate > 5:
            if health_status == "healthy":
                health_status = "warning"
            issues.append(f"Elevated error rate: {error_rate:.1f}%")
        
        # Check average response time
        avg_response_time = self.get_average_response_time()
        if avg_response_time > 5000:  # 5 seconds
            health_status = "critical"
            issues.append(f"High response time: {avg_response_time:.0f}ms")
        elif avg_response_time > 2000:  # 2 seconds
            if health_status == "healthy":
                health_status = "warning"
            issues.append(f"Elevated response time: {avg_response_time:.0f}ms")
        
        self.status = health_status
        
        return {
            'status': health_status,
            'issues': issues,
            'system_metrics': system_metrics,
            'uptime_hours': self.get_uptime(),
            'error_rate': error_rate,
            'average_response_time': avg_response_time,
            'last_check': time.time()
        }
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """
        Get current system metrics.
        
        Returns:
            Dictionary containing system resource usage
        """
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available / (1024**3)  # GB
            memory_total = memory.total / (1024**3)  # GB
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free = disk.free / (1024**3)  # GB
            disk_total = disk.total / (1024**3)  # GB
            
            # Network I/O
            network = psutil.net_io_counters()
            
            # Process info
            process = psutil.Process()
            process_memory = process.memory_info().rss / (1024**2)  # MB
            process_cpu = process.cpu_percent()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'memory_available_gb': round(memory_available, 2),
                'memory_total_gb': round(memory_total, 2),
                'disk_percent': disk_percent,
                'disk_free_gb': round(disk_free, 2),
                'disk_total_gb': round(disk_total, 2),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'process_memory_mb': round(process_memory, 2),
                'process_cpu_percent': process_cpu,
                'timestamp': time.time()
            }
        
        except Exception as e:
            return {
                'error': f"Failed to get system metrics: {str(e)}",
                'timestamp': time.time()
            }
    
    def get_error_rate(self) -> float:
        """
        Calculate the error rate percentage.
        
        Returns:
            Error rate as percentage
        """
        if self.total_checks == 0:
            return 0.0
        
        return (self.error_count / self.total_checks) * 100.0
    
    def get_average_response_time(self) -> float:
        """
        Calculate the average response time.
        
        Returns:
            Average response time in milliseconds
        """
        if not self.response_times:
            return 0.0
        
        return sum(self.response_times) / len(self.response_times)
    
    def get_health_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive health summary.
        
        Returns:
            Dictionary containing health summary
        """
        return {
            'status': self.status,
            'uptime_hours': round(self.get_uptime(), 2),
            'uptime_days': round(self.get_uptime() / 24, 2),
            'error_count': self.error_count,
            'total_checks': self.total_checks,
            'error_rate': round(self.get_error_rate(), 2),
            'average_response_time': round(self.get_average_response_time(), 2),
            'max_response_time': round(self.max_response_time, 2),
            'last_health_check': self.last_health_check,
            'system_metrics': self.get_system_metrics()
        }
    
    def is_healthy(self) -> bool:
        """
        Check if the system is currently healthy.
        
        Returns:
            True if status is healthy, False otherwise
        """
        return self.status == "healthy"
    
    def reset_metrics(self) -> None:
        """Reset all health metrics."""
        self.start_time = time.time()
        self.last_health_check = time.time()
        self.status = "healthy"
        self.error_count = 0
        self.total_checks = 0
        self.response_times.clear()
        self.max_response_time = 0.0 