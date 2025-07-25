import re
import time
from typing import Dict, Any, List, Optional
from collections import defaultdict


class SecurityMonitor:
    """
    Monitors security events and compliance for AI agents.
    
    This class provides threat detection, PII scanning, and compliance
    monitoring capabilities for AI agent operations.
    """
    
    def __init__(self):
        """Initialize the security monitor."""
        self.security_events: List[Dict[str, Any]] = []
        self.compliance_logs: List[Dict[str, Any]] = []
        self.threat_patterns = self._initialize_threat_patterns()
        self.pii_patterns = self._initialize_pii_patterns()
        
        # Event counters
        self.event_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
    
    def _initialize_threat_patterns(self) -> Dict[str, List[str]]:
        """
        Initialize patterns for threat detection.
        
        Returns:
            Dictionary of threat patterns
        """
        return {
            'sql_injection': [
                r"(?i)(union\s+select)",
                r"(?i)(drop\s+table)",
                r"(?i)(insert\s+into)",
                r"(?i)(delete\s+from)",
                r"(?i)(update\s+\w+\s+set)",
                r"(?i)(\'\s*or\s+\'\d+\'\s*=\s*\'\d+)",
                r"(?i)(\'\s*or\s+\d+\s*=\s*\d+)",
                r"(?i)(--\s*$)",
                r"(?i)(/\*.*\*/)"
            ],
            'xss': [
                r"(?i)(<script[^>]*>)",
                r"(?i)(<iframe[^>]*>)",
                r"(?i)(javascript:)",
                r"(?i)(on\w+\s*=)",
                r"(?i)(<img[^>]*onerror)",
                r"(?i)(<svg[^>]*onload)",
                r"(?i)(expression\s*\()",
                r"(?i)(vbscript:)"
            ],
            'command_injection': [
                r"(?i)(;\s*rm\s+-rf)",
                r"(?i)(;\s*cat\s+/etc/passwd)",
                r"(?i)(;\s*wget\s+)",
                r"(?i)(;\s*curl\s+)",
                r"(?i)(\|\s*nc\s+)",
                r"(?i)(\$\(.*\))",
                r"(?i)(`.*`)",
                r"(?i)(;\s*exec\s+)"
            ],
            'path_traversal': [
                r"(\.\./){2,}",
                r"(\.\.\\){2,}",
                r"(?i)(file://)",
                r"(?i)(/etc/passwd)",
                r"(?i)(/windows/system32)",
                r"(?i)(\.\.%2f)",
                r"(?i)(\.\.%5c)"
            ]
        }
    
    def _initialize_pii_patterns(self) -> Dict[str, str]:
        """
        Initialize patterns for PII detection.
        
        Returns:
            Dictionary of PII patterns
        """
        return {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'url': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:\w)*)?'
        }
    
    def analyze_request_security(self, operation: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request data for security threats.
        
        Args:
            operation: The operation being performed
            request_data: Data to analyze for threats
            
        Returns:
            Dictionary containing security analysis results
        """
        analysis_start = time.time()
        threats_detected = []
        severity = "low"
        
        # Convert request data to string for analysis
        content = str(request_data.get('content', ''))
        
        # Check for various threat types
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    threat_info = {
                        'type': threat_type,
                        'pattern': pattern,
                        'severity': self._get_threat_severity(threat_type)
                    }
                    threats_detected.append(threat_info)
                    
                    # Update overall severity
                    if threat_info['severity'] == 'critical':
                        severity = 'critical'
                    elif threat_info['severity'] == 'high' and severity != 'critical':
                        severity = 'high'
                    elif threat_info['severity'] == 'medium' and severity not in ['critical', 'high']:
                        severity = 'medium'
        
        # Log security event if threats detected
        if threats_detected:
            self.log_security_event(
                event_type='threat_detection',
                description=f"Detected {len(threats_detected)} security threats in {operation}",
                severity=severity,
                metadata={
                    'operation': operation,
                    'threats': threats_detected,
                    'content_length': len(content)
                }
            )
        
        analysis_time = (time.time() - analysis_start) * 1000  # milliseconds
        
        return {
            'threats_detected': threats_detected,
            'threat_count': len(threats_detected),
            'severity': severity,
            'safe': len(threats_detected) == 0,
            'analysis_time_ms': round(analysis_time, 2),
            'timestamp': time.time()
        }
    
    def check_data_privacy(self, text: str) -> Dict[str, Any]:
        """
        Check text for PII and privacy concerns.
        
        Args:
            text: Text to analyze for PII
            
        Returns:
            Dictionary containing privacy analysis results
        """
        analysis_start = time.time()
        pii_detected = []
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                pii_info = {
                    'type': pii_type,
                    'count': len(matches),
                    'matches': matches[:5],  # Limit to first 5 matches for privacy
                    'severity': self._get_pii_severity(pii_type)
                }
                pii_detected.append(pii_info)
        
        # Determine overall compliance status
        if any(pii['severity'] in ['high', 'critical'] for pii in pii_detected):
            compliance_status = 'non_compliant'
            severity = 'high'
        elif pii_detected:
            compliance_status = 'warning'
            severity = 'medium'
        else:
            compliance_status = 'compliant'
            severity = 'low'
        
        # Log compliance event
        self.log_compliance_event(
            compliance_type='pii_detection',
            status=compliance_status,
            details=f"Detected {len(pii_detected)} types of PII in data",
            metadata={
                'pii_types': [pii['type'] for pii in pii_detected],
                'total_pii_count': sum(pii['count'] for pii in pii_detected),
                'text_length': len(text)
            }
        )
        
        analysis_time = (time.time() - analysis_start) * 1000  # milliseconds
        
        return {
            'pii_detected': pii_detected,
            'pii_types_count': len(pii_detected),
            'total_pii_instances': sum(pii['count'] for pii in pii_detected),
            'compliance_status': compliance_status,
            'severity': severity,
            'privacy_safe': len(pii_detected) == 0,
            'analysis_time_ms': round(analysis_time, 2),
            'timestamp': time.time()
        }
    
    def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            description: Description of the event
            severity: Event severity (low, medium, high, critical)
            metadata: Additional event metadata
        """
        event = {
            'id': len(self.security_events) + 1,
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'metadata': metadata or {},
            'timestamp': time.time()
        }
        
        self.security_events.append(event)
        self.event_counts[event_type] += 1
        self.severity_counts[severity] += 1
        
        # Keep only last 1000 events for performance
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
    
    def log_compliance_event(
        self,
        compliance_type: str,
        status: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a compliance event.
        
        Args:
            compliance_type: Type of compliance check
            status: Compliance status (compliant, non_compliant, warning)
            details: Details of the compliance check
            metadata: Additional compliance metadata
        """
        event = {
            'id': len(self.compliance_logs) + 1,
            'compliance_type': compliance_type,
            'status': status,
            'details': details,
            'metadata': metadata or {},
            'timestamp': time.time()
        }
        
        self.compliance_logs.append(event)
        
        # Keep only last 1000 logs for performance
        if len(self.compliance_logs) > 1000:
            self.compliance_logs = self.compliance_logs[-1000:]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive security summary.
        
        Returns:
            Dictionary containing security summary
        """
        recent_events = [
            event for event in self.security_events 
            if time.time() - event['timestamp'] < 3600  # Last hour
        ]
        
        recent_compliance = [
            log for log in self.compliance_logs 
            if time.time() - log['timestamp'] < 3600  # Last hour
        ]
        
        return {
            'total_security_events': len(self.security_events),
            'recent_events_count': len(recent_events),
            'event_types': dict(self.event_counts),
            'severity_distribution': dict(self.severity_counts),
            'total_compliance_logs': len(self.compliance_logs),
            'recent_compliance_count': len(recent_compliance),
            'latest_security_events': self.security_events[-5:] if self.security_events else [],
            'latest_compliance_logs': self.compliance_logs[-5:] if self.compliance_logs else [],
            'security_score': self._calculate_security_score(),
            'compliance_score': self._calculate_compliance_score()
        }
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """
        Get severity level for a threat type.
        
        Args:
            threat_type: Type of threat
            
        Returns:
            Severity level
        """
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'xss': 'high',
            'path_traversal': 'high'
        }
        return severity_map.get(threat_type, 'medium')
    
    def _get_pii_severity(self, pii_type: str) -> str:
        """
        Get severity level for a PII type.
        
        Args:
            pii_type: Type of PII
            
        Returns:
            Severity level
        """
        severity_map = {
            'ssn': 'critical',
            'credit_card': 'critical',
            'email': 'medium',
            'phone': 'medium',
            'ip_address': 'low',
            'url': 'low'
        }
        return severity_map.get(pii_type, 'medium')
    
    def _calculate_security_score(self) -> float:
        """
        Calculate an overall security score (0-100).
        
        Returns:
            Security score percentage
        """
        if not self.security_events:
            return 100.0
        
        # Recent events (last 24 hours) have more weight
        recent_cutoff = time.time() - 86400  # 24 hours
        recent_events = [
            event for event in self.security_events 
            if event['timestamp'] > recent_cutoff
        ]
        
        # Calculate deductions based on severity
        deductions = 0
        for event in recent_events:
            severity = event['severity']
            if severity == 'critical':
                deductions += 20
            elif severity == 'high':
                deductions += 10
            elif severity == 'medium':
                deductions += 5
            elif severity == 'low':
                deductions += 1
        
        score = max(0, 100 - deductions)
        return round(score, 1)
    
    def _calculate_compliance_score(self) -> float:
        """
        Calculate an overall compliance score (0-100).
        
        Returns:
            Compliance score percentage
        """
        if not self.compliance_logs:
            return 100.0
        
        # Recent logs (last 24 hours)
        recent_cutoff = time.time() - 86400  # 24 hours
        recent_logs = [
            log for log in self.compliance_logs 
            if log['timestamp'] > recent_cutoff
        ]
        
        if not recent_logs:
            return 100.0
        
        # Calculate score based on compliance status
        compliant_count = sum(1 for log in recent_logs if log['status'] == 'compliant')
        warning_count = sum(1 for log in recent_logs if log['status'] == 'warning')
        non_compliant_count = sum(1 for log in recent_logs if log['status'] == 'non_compliant')
        
        total_logs = len(recent_logs)
        
        # Weighted score calculation
        score = (
            (compliant_count * 100) +
            (warning_count * 50) +
            (non_compliant_count * 0)
        ) / total_logs
        
        return round(score, 1) 