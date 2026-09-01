"""Core header analyzer and industry-standard security scoring engine."""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from app.schemas import Finding, SeverityCount


class HeaderAnalyzer:
    """Main analyzer for HTTP security headers."""
    
    def __init__(self, headers: Dict[str, str]):
        self.headers = {k.lower(): str(v) for k, v in headers.items()}
        self.findings: List[Finding] = []
    
    def analyze(self) -> Tuple[List[Finding], SeverityCount, float]:
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
        
        severity_counts = self._calculate_severity_counts()
        security_score = self._calculate_security_score()
        
        return self.findings, severity_counts, security_score
    
    def _calculate_severity_counts(self) -> SeverityCount:
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
    
    def _calculate_security_score(self) -> float:
        """
        Industry-standard weighted scoring model (0-100):
        - HSTS: 25 pts
        - CSP: 25 pts
        - X-Frame-Options: 15 pts
        - X-Content-Type-Options: 15 pts
        - Referrer-Policy: 10 pts
        - Permissions-Policy: 10 pts
        """
        score = 0.0
        
        # 1. HSTS (25 points)
        if "strict-transport-security" in self.headers:
            hsts_val = self.headers["strict-transport-security"].lower()
            if "max-age" in hsts_val:
                score += 15.0
                if "includesubdomains" in hsts_val:
                    score += 5.0
                if "preload" in hsts_val:
                    score += 5.0
        
        # 2. CSP (25 points)
        csp = self.headers.get("content-security-policy") or self.headers.get("content-security-policy-report-only")
        if csp:
            csp_lower = csp.lower()
            score += 15.0
            if "'unsafe-inline'" not in csp_lower:
                score += 5.0
            if "'unsafe-eval'" not in csp_lower:
                score += 5.0
        
        # 3. X-Frame-Options / CSP frame-ancestors (15 points)
        xfo = self.headers.get("x-frame-options", "").lower()
        if xfo in ("deny", "sameorigin") or (csp and "frame-ancestors" in csp.lower()):
            score += 15.0
        elif xfo:
            score += 8.0
            
        # 4. X-Content-Type-Options (15 points)
        if self.headers.get("x-content-type-options", "").strip().lower() == "nosniff":
            score += 15.0
            
        # 5. Referrer-Policy (10 points)
        ref_pol = self.headers.get("referrer-policy", "").strip().lower()
        if ref_pol in ("strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"):
            score += 10.0
        elif ref_pol and ref_pol != "unsafe-url":
            score += 6.0
            
        # 6. Permissions-Policy / Feature-Policy (10 points)
        if "permissions-policy" in self.headers or "feature-policy" in self.headers:
            score += 10.0
            
        # Penalties for critical misconfigurations
        cors_origin = self.headers.get("access-control-allow-origin", "")
        cors_creds = self.headers.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*" and cors_creds == "true":
            score = max(0.0, score - 30.0)
            
        return round(max(0.0, min(100.0, score)), 1)
