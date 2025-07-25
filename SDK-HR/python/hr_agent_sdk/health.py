import time
import psutil
from typing import Optional, Dict, Any

class HealthMonitor:
    """
    Monitors agent health and system metrics
    """
    
    def __init__(self):
        self.start_time = time.time()
        self.status = "healthy"
        self.last_error: Optional[str] = None
        self.error_count = 0
    
    def update_status(self, status: str, memory_usage: Optional[float] = None, cpu_usage: Optional[float] = None):
        """Update health status manually"""
        self.status = status
        
        # Auto-detect system metrics if not provided
        if memory_usage is None or cpu_usage is None:
            try:
                process = psutil.Process()
                if memory_usage is None:
                    memory_usage = process.memory_info().rss / 1024 / 1024  # MB
                if cpu_usage is None:
                    cpu_usage = process.cpu_percent()
            except:
                # If psutil fails, use defaults
                memory_usage = memory_usage or 0.0
                cpu_usage = cpu_usage or 0.0
    
    def get_uptime(self) -> float:
        """Get uptime in seconds"""
        return time.time() - self.start_time
    
    def log_error(self, error_message: str):
        """Log an error and update status"""
        self.last_error = error_message
        self.error_count += 1
        
        # Update status based on error frequency
        if self.error_count > 10:
            self.status = "unhealthy"
        elif self.error_count > 5:
            self.status = "degraded"
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                "memory_usage_mb": round(memory_info.rss / 1024 / 1024, 2),
                "cpu_usage_percent": round(process.cpu_percent(), 2),
                "memory_percent": round(process.memory_percent(), 2),
                "num_threads": process.num_threads(),
                "uptime_seconds": round(self.get_uptime(), 0)
            }
        except Exception as e:
            # Fallback if psutil is not available
            return {
                "memory_usage_mb": 0.0,
                "cpu_usage_percent": 0.0,
                "memory_percent": 0.0,
                "num_threads": 1,
                "uptime_seconds": round(self.get_uptime(), 0),
                "error": f"Could not get system metrics: {str(e)}"
            }
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get complete health summary"""
        system_metrics = self.get_system_metrics()
        
        return {
            "status": self.status,
            "uptime_seconds": round(self.get_uptime(), 0),
            "error_count": self.error_count,
            "last_error": self.last_error,
            "memory_usage_mb": system_metrics.get("memory_usage_mb", 0.0),
            "cpu_usage_percent": system_metrics.get("cpu_usage_percent", 0.0),
            "timestamp": time.time()
        }
    
    def reset_errors(self):
        """Reset error count and status"""
        self.error_count = 0
        self.last_error = None
        self.status = "healthy" 