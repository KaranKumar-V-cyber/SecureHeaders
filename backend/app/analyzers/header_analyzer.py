"""Core header analyzer logic."""

from typing import Dict, List, Any, Optional
from datetime import datetime
from app.schemas import Finding, SeverityCount


class HeaderAnalyzer:
    """Main analyzer for HTTP security headers."""
    
    def __init__(self, headers: Dict[str, str]):
        """Initialize with response headers."""
        self.headers = {k.lower(): v for k, v in headers.items()}  # Normalize keys
        self.findings: List[Finding] = []
    
    def analyze(self) -> tuple[List[Finding], SeverityCount, float]:
        """
        Analyze all security headers.
        
        Returns:
            Tuple of (findings, severity_counts, security_score)
        """
        # Import analyzers
        from app.analyzers.csp_analyzer import analyze_csp
        from app.analyzers.hsts_analyzer import analyze_hsts
        from app.analyzers.cors_analyzer import analyze_cors
        from app.analyzers.cookie_analyzer import analyze_cookies
        from app.analyzers.cache_analyzer import analyze_cache
        from app.analyzers.frame_options_analyzer import analyze_frame_options
        from app.analyzers.content_type_analyzer import analyze_content_type
        from app.analyzers.referrer_policy_analyzer import analyze_referrer_policy
        from app.analyzers.permissions_policy_analyzer import analyze_permissions_policy
        
        # Run all analyzers
        self.findings.extend(analyze_csp(self.headers))
        self.findings.extend(analyze_hsts(self.headers))
        self.findings.extend(analyze_cors(self.headers))
        self.findings.extend(analyze_cookies(self.headers))
        self.findings.extend(analyze_cache(self.headers))
        self.findings.extend(analyze_frame_options(self.headers))
        self.findings.extend(analyze_content_type(self.headers))
        self.findings.extend(analyze_referrer_policy(self.headers))
        self.findings.extend(analyze_permissions_policy(self.headers))
        
        # Calculate severity counts
        severity_counts = self._calculate_severity_counts()
        
        # Calculate security score
        security_score = self._calculate_security_score(severity_counts)
        
        return self.findings, severity_counts, security_score
    
    def _calculate_severity_counts(self) -> SeverityCount:
        """Count findings by severity."""
        counts = SeverityCount()
        
        for finding in self.findings:
            if finding.severity == "CRITICAL":
                counts.CRITICAL += 1
            elif finding.severity == "HIGH":
                counts.HIGH += 1
            elif finding.severity == "MEDIUM":
                counts.MEDIUM += 1
            elif finding.severity == "LOW":
                counts.LOW += 1
            elif finding.severity == "INFO":
                counts.INFO += 1
        
        return counts
    
    def _calculate_security_score(self, severity_counts: SeverityCount) -> float:
        """
        Calculate security score from 0-100.
        
        Deductions:
        - Critical: 25 points
        - High: 15 points
        - Medium: 7 points
        - Low: 2 points
        - Info: 0 points
        """
        base_score = 100.0
        
        deductions = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 7,
            "LOW": 2,
            "INFO": 0,
        }
        
        total_deduction = (
            severity_counts.CRITICAL * deductions["CRITICAL"] +
            severity_counts.HIGH * deductions["HIGH"] +
            severity_counts.MEDIUM * deductions["MEDIUM"] +
            severity_counts.LOW * deductions["LOW"] +
            severity_counts.INFO * deductions["INFO"]
        )
        
        score = max(0, min(100, base_score - total_deduction))
        return round(score, 2)
    
    def get_findings(self) -> List[Finding]:
        """Get all findings."""
        return self.findings
    
    def get_header(self, name: str) -> Optional[str]:
        """Get header value case-insensitively."""
        return self.headers.get(name.lower())
    
    def has_header(self, name: str) -> bool:
        """Check if header exists case-insensitively."""
        return name.lower() in self.headers
