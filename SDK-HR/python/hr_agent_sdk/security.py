import time
import hashlib
import re
from typing import List, Dict, Any, Optional

class SecurityMonitor:
    """
    Monitors security events and compliance for AI agents
    """
    
    def __init__(self):
        self.security_events: List[Dict[str, Any]] = []
        self.compliance_logs: List[Dict[str, Any]] = []
        self.threat_indicators = {
            'suspicious_patterns': [
                r'(?i)(password|secret|key|token)\s*[:=]\s*["\']?[a-zA-Z0-9]+',
                r'(?i)(admin|root|administrator)',
                r'(?i)(drop|delete|truncate)\s+(table|database)',
                r'(?i)union\s+select',
                r'(?i)<script[^>]*>.*?</script>',
            ],
            'data_patterns': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            ]
        }
    
    def analyze_request_security(self, request_data: str, user_input: str = "") -> Dict[str, Any]:
        """
        Analyze a request for security threats
        """
        threats = []
        threat_level = 0
        
        # Check for suspicious patterns
        for pattern in self.threat_indicators['suspicious_patterns']:
            if re.search(pattern, request_data + " " + user_input):
                threats.append(f"Suspicious pattern detected: {pattern}")
                threat_level += 20
        
        # Check for data exposure
        for pattern in self.threat_indicators['data_patterns']:
            matches = re.findall(pattern, request_data + " " + user_input)
            if matches:
                threats.append(f"Potential data exposure: {len(matches)} sensitive data patterns")
                threat_level += 30
        
        # Check request size (potential DoS)
        if len(request_data) > 100000:  # 100KB
            threats.append("Large request size detected")
            threat_level += 10
        
        # Determine severity
        if threat_level >= 70:
            severity = "critical"
        elif threat_level >= 50:
            severity = "high"
        elif threat_level >= 30:
            severity = "medium"
        else:
            severity = "low"
        
        return {
            "threat_level": min(threat_level, 100),
            "severity": severity,
            "threats": threats,
            "analyzed_at": time.time()
        }
    
    def log_security_event(
        self, 
        event_type: str, 
        description: str, 
        severity: str = "medium",
        source_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        blocked: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log a security event
        """
        event = {
            "event_type": event_type,
            "description": description,
            "severity": severity,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "blocked": blocked,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
        
        self.security_events.append(event)
        return event
    
    def log_compliance_event(
        self,
        compliance_type: str,
        event_description: str,
        data_processed: Optional[Dict[str, Any]] = None,
        user_consent: Optional[bool] = None,
        encryption_status: bool = True,
        data_location: str = "cloud",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log a compliance event (GDPR, HIPAA, etc.)
        """
        event = {
            "compliance_type": compliance_type,
            "event_description": event_description,
            "data_processed": data_processed,
            "user_consent": user_consent,
            "encryption_status": encryption_status,
            "data_location": data_location,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
        
        self.compliance_logs.append(event)
        return event
    
    def check_data_privacy(self, text: str) -> Dict[str, Any]:
        """
        Check text for potential privacy violations
        """
        findings = []
        
        # Check for PII patterns
        patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        }
        
        for pii_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings.append({
                    "type": pii_type,
                    "count": len(matches),
                    "samples": [self._mask_sensitive_data(match) for match in matches[:3]]
                })
        
        return {
            "has_pii": len(findings) > 0,
            "findings": findings,
            "risk_level": "high" if len(findings) > 0 else "low"
        }
    
    def _mask_sensitive_data(self, data: str) -> str:
        """
        Mask sensitive data for logging
        """
        if len(data) <= 4:
            return "*" * len(data)
        return data[:2] + "*" * (len(data) - 4) + data[-2:]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get security summary
        """
        total_events = len(self.security_events)
        critical_events = sum(1 for e in self.security_events if e.get('severity') == 'critical')
        blocked_events = sum(1 for e in self.security_events if e.get('blocked', False))
        
        return {
            "total_security_events": total_events,
            "critical_events": critical_events,
            "blocked_events": blocked_events,
            "compliance_logs": len(self.compliance_logs),
            "last_event": self.security_events[-1]['timestamp'] if self.security_events else None
        }
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        """
        return {
            "summary": self.get_security_summary(),
            "recent_events": self.security_events[-10:],  # Last 10 events
            "compliance_status": self.compliance_logs[-5:],  # Last 5 compliance logs
            "generated_at": time.time()
        } 