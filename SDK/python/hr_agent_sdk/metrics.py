import time
from typing import Dict, Any, List
from collections import defaultdict


class MetricsCollector:
    """
    Collects and aggregates local metrics for an AI agent.
    
    This class tracks tokens, costs, latency, success rates, and errors
    locally before sending to the backend.
    """
    
    def __init__(self):
        """Initialize the metrics collector."""
        self.start_time = time.time()
        
        # Token and cost tracking
        self.total_tokens = 0
        self.total_cost = 0.0
        
        # Request tracking
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        
        # Latency tracking
        self.latencies: List[float] = []
        
        # Error tracking
        self.errors: Dict[str, int] = defaultdict(int)
        
        # Hourly metrics for time-series data
        self.hourly_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'tokens': 0,
            'cost': 0.0,
            'requests': 0,
            'avg_latency': 0.0,
            'errors': 0
        })
    
    def update_tokens(self, tokens: int, cost: float = 0.0) -> None:
        """
        Update token usage and cost.
        
        Args:
            tokens: Number of tokens used
            cost: Cost of the operation
        """
        self.total_tokens += tokens
        self.total_cost += cost
        
        # Update hourly metrics
        hour_key = self._get_current_hour_key()
        self.hourly_metrics[hour_key]['tokens'] += tokens
        self.hourly_metrics[hour_key]['cost'] += cost
    
    def update_request(self, latency: float, success: bool = True) -> None:
        """
        Update request metrics.
        
        Args:
            latency: Request latency in milliseconds
            success: Whether the request was successful
        """
        self.total_requests += 1
        self.latencies.append(latency)
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        
        # Update hourly metrics
        hour_key = self._get_current_hour_key()
        self.hourly_metrics[hour_key]['requests'] += 1
        
        # Update average latency for this hour
        current_avg = self.hourly_metrics[hour_key]['avg_latency']
        current_count = self.hourly_metrics[hour_key]['requests']
        
        if current_count == 1:
            self.hourly_metrics[hour_key]['avg_latency'] = latency
        else:
            # Running average calculation
            self.hourly_metrics[hour_key]['avg_latency'] = (
                (current_avg * (current_count - 1) + latency) / current_count
            )
    
    def update_error(self, error_type: str) -> None:
        """
        Update error count.
        
        Args:
            error_type: Type of error that occurred
        """
        self.errors[error_type] += 1
        
        # Update hourly metrics
        hour_key = self._get_current_hour_key()
        self.hourly_metrics[hour_key]['errors'] += 1
    
    def get_success_rate(self) -> float:
        """
        Calculate the success rate as a percentage.
        
        Returns:
            Success rate percentage (0-100)
        """
        if self.total_requests == 0:
            return 100.0
        
        return (self.successful_requests / self.total_requests) * 100.0
    
    def get_average_latency(self) -> float:
        """
        Calculate the average latency.
        
        Returns:
            Average latency in milliseconds
        """
        if not self.latencies:
            return 0.0
        
        return sum(self.latencies) / len(self.latencies)
    
    def get_error_rate(self) -> float:
        """
        Calculate the error rate as a percentage.
        
        Returns:
            Error rate percentage (0-100)
        """
        if self.total_requests == 0:
            return 0.0
        
        return (self.failed_requests / self.total_requests) * 100.0
    
    def get_cost_per_request(self) -> float:
        """
        Calculate the average cost per request.
        
        Returns:
            Average cost per request
        """
        if self.total_requests == 0:
            return 0.0
        
        return self.total_cost / self.total_requests
    
    def get_tokens_per_request(self) -> float:
        """
        Calculate the average tokens per request.
        
        Returns:
            Average tokens per request
        """
        if self.total_requests == 0:
            return 0.0
        
        return self.total_tokens / self.total_requests
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive summary of all metrics.
        
        Returns:
            Dictionary containing all metric summaries
        """
        uptime = time.time() - self.start_time
        
        return {
            'uptime_seconds': uptime,
            'uptime_hours': uptime / 3600,
            'total_tokens': self.total_tokens,
            'total_cost': round(self.total_cost, 4),
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'success_rate': round(self.get_success_rate(), 2),
            'error_rate': round(self.get_error_rate(), 2),
            'average_latency': round(self.get_average_latency(), 2),
            'cost_per_request': round(self.get_cost_per_request(), 4),
            'tokens_per_request': round(self.get_tokens_per_request(), 2),
            'error_breakdown': dict(self.errors),
            'requests_per_hour': round(self.total_requests / (uptime / 3600), 2) if uptime > 0 else 0,
            'cost_per_hour': round(self.total_cost / (uptime / 3600), 4) if uptime > 0 else 0
        }
    
    def get_hourly_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """
        Get hourly breakdown of metrics.
        
        Returns:
            Dictionary with hourly metrics
        """
        return dict(self.hourly_metrics)
    
    def reset_metrics(self) -> None:
        """Reset all metrics to initial state."""
        self.start_time = time.time()
        self.total_tokens = 0
        self.total_cost = 0.0
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.latencies.clear()
        self.errors.clear()
        self.hourly_metrics.clear()
    
    def _get_current_hour_key(self) -> str:
        """
        Get the current hour as a string key.
        
        Returns:
            Hour key in format 'YYYY-MM-DD-HH'
        """
        current_time = time.time()
        time_struct = time.localtime(current_time)
        return f"{time_struct.tm_year}-{time_struct.tm_mon:02d}-{time_struct.tm_mday:02d}-{time_struct.tm_hour:02d}" 