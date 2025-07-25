import time
from typing import List, Dict, Any

class MetricsCollector:
    """
    Collects and stores agent metrics locally for aggregation
    """
    
    def __init__(self):
        self.total_tokens = 0
        self.total_cost = 0.0
        self.request_count = 0
        self.error_count = 0
        self.latencies: List[float] = []
        self.start_time = time.time()
    
    def update_tokens(self, prompt_tokens: int, completion_tokens: int, cost: float):
        """Update token and cost metrics"""
        self.total_tokens += prompt_tokens + completion_tokens
        self.total_cost += cost
        self.request_count += 1
    
    def update_latency(self, latency: float):
        """Update latency metrics"""
        self.latencies.append(latency)
        
        # Keep only last 100 latencies to prevent memory growth
        if len(self.latencies) > 100:
            self.latencies = self.latencies[-100:]
    
    def increment_errors(self):
        """Increment error count"""
        self.error_count += 1
    
    def get_average_latency(self) -> float:
        """Get average latency in seconds"""
        if not self.latencies:
            return 0.0
        return sum(self.latencies) / len(self.latencies)
    
    def get_error_rate(self) -> float:
        """Get error rate as percentage"""
        if self.request_count == 0:
            return 0.0
        return (self.error_count / (self.request_count + self.error_count)) * 100
    
    def get_summary(self) -> Dict[str, Any]:
        """Get complete metrics summary"""
        return {
            "total_tokens": self.total_tokens,
            "total_cost": round(self.total_cost, 6),
            "request_count": self.request_count,
            "error_count": self.error_count,
            "average_latency": round(self.get_average_latency(), 3),
            "error_rate": round(self.get_error_rate(), 2),
            "uptime": round(time.time() - self.start_time, 0)
        }
    
    def reset(self):
        """Reset all metrics"""
        self.total_tokens = 0
        self.total_cost = 0.0
        self.request_count = 0
        self.error_count = 0
        self.latencies = []
        self.start_time = time.time() 