"""Tests for header analyzers."""

import pytest
from app.analyzers.csp_analyzer import analyze_csp
from app.analyzers.hsts_analyzer import analyze_hsts
from app.analyzers.cookie_analyzer import analyze_cookies


class TestCSPAnalyzer:
    """Test CSP header analysis."""

    def test_missing_csp(self):
        """Test detection of missing CSP."""
        headers = {}
        findings = analyze_csp(headers)
        
        assert len(findings) > 0
        assert any(f.title == "Content-Security-Policy Header Missing" for f in findings)
        assert any(f.severity == "HIGH" for f in findings)

    def test_csp_present(self):
        """Test detection of present CSP."""
        headers = {"content-security-policy": "default-src 'self'"}
        findings = analyze_csp(headers)
        
        # Should not report missing CSP
        assert not any(f.title == "Content-Security-Policy Header Missing" for f in findings)

    def test_csp_unsafe_inline(self):
        """Test detection of unsafe-inline."""
        headers = {"content-security-policy": "script-src 'self' 'unsafe-inline'"}
        findings = analyze_csp(headers)
        
        assert any("unsafe-inline" in f.title.lower() for f in findings)

    def test_csp_unsafe_eval(self):
        """Test detection of unsafe-eval."""
        headers = {"content-security-policy": "script-src 'self' 'unsafe-eval'"}
        findings = analyze_csp(headers)
        
        assert any("unsafe-eval" in f.title.lower() for f in findings)


class TestHSTSAnalyzer:
    """Test HSTS header analysis."""

    def test_missing_hsts(self):
        """Test detection of missing HSTS."""
        headers = {}
        findings = analyze_hsts(headers)
        
        assert len(findings) > 0
        assert any(f.title == "Strict-Transport-Security Header Missing" for f in findings)
        assert any(f.severity == "HIGH" for f in findings)

    def test_valid_hsts(self):
        """Test valid HSTS configuration."""
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        }
        findings = analyze_hsts(headers)
        
        # Should not report critical issues
        assert not any(f.severity == "HIGH" for f in findings)

    def test_hsts_short_max_age(self):
        """Test detection of short max-age."""
        headers = {"strict-transport-security": "max-age=3600"}
        findings = analyze_hsts(headers)
        
        assert any("max-age" in f.title.lower() and "short" in f.title.lower() for f in findings)

    def test_hsts_missing_subdomains(self):
        """Test detection of missing includeSubDomains."""
        headers = {"strict-transport-security": "max-age=31536000"}
        findings = analyze_hsts(headers)
        
        assert any("includesubdomains" in f.title.lower() for f in findings)


class TestCookieAnalyzer:
    """Test cookie security analysis."""

    def test_no_cookies(self):
        """Test when no cookies are present."""
        headers = {}
        findings = analyze_cookies(headers)
        
        assert any("no cookies" in f.title.lower() for f in findings)

    def test_cookie_missing_secure(self):
        """Test detection of missing Secure flag."""
        headers = {"set-cookie": "sessionid=abc123; HttpOnly"}
        findings = analyze_cookies(headers)
        
        assert any("secure" in f.title.lower() for f in findings)

    def test_cookie_missing_httponly(self):
        """Test detection of missing HttpOnly flag."""
        headers = {"set-cookie": "sessionid=abc123; Secure"}
        findings = analyze_cookies(headers)
        
        assert any("httponly" in f.title.lower() for f in findings)

    def test_secure_cookie(self):
        """Test fully secure cookie."""
        headers = {
            "set-cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Strict"
        }
        findings = analyze_cookies(headers)
        
        # Should not report security issues
        critical_findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(critical_findings) == 0


class TestAdditionalAnalyzers:
    """Test remaining analyzers and score calculation."""

    def test_cors_wildcard_credentials(self):
        from app.analyzers.cors_analyzer import analyze_cors
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true"
        }
        findings = analyze_cors(headers)
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_cache_missing_control(self):
        from app.analyzers.cache_analyzer import analyze_cache
        headers = {}
        findings = analyze_cache(headers)
        assert any("missing" in f.title.lower() for f in findings)

    def test_frame_options_missing(self):
        from app.analyzers.frame_options_analyzer import analyze_frame_options
        headers = {}
        findings = analyze_frame_options(headers)
        assert any("missing" in f.title.lower() for f in findings)

    def test_content_type_options_nosniff(self):
        from app.analyzers.content_type_analyzer import analyze_content_type
        headers = {"x-content-type-options": "nosniff"}
        findings = analyze_content_type(headers)
        assert any(f.severity == "INFO" for f in findings)

    def test_referrer_policy_unsafe_url(self):
        from app.analyzers.referrer_policy_analyzer import analyze_referrer_policy
        headers = {"referrer-policy": "unsafe-url"}
        findings = analyze_referrer_policy(headers)
        assert any(f.severity == "HIGH" for f in findings)

    def test_permissions_policy_comma_separated(self):
        from app.analyzers.permissions_policy_analyzer import analyze_permissions_policy
        headers = {"permissions-policy": "camera=*, microphone=(), geolocation=()"}
        findings = analyze_permissions_policy(headers)
        assert any("camera" in f.title.lower() and f.severity == "HIGH" for f in findings)

    def test_header_analyzer_scoring(self):
        from app.analyzers.header_analyzer import HeaderAnalyzer
        headers = {
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=()",
            "cache-control": "no-store, no-cache, must-revalidate",
            "set-cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
        }
        analyzer = HeaderAnalyzer(headers)
        findings, counts, score = analyzer.analyze()
        assert score >= 90
        assert counts.CRITICAL == 0
        assert counts.HIGH == 0
