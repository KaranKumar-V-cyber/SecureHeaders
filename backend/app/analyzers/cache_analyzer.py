"""Cache-related headers analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_cache(headers: Dict[str, str]) -> List[Finding]:
    """Analyze cache-related headers."""
    findings = []
    
    cache_control = _get_header(headers, "cache-control")
    pragma = _get_header(headers, "pragma")
    expires = _get_header(headers, "expires")
    
    # Check Cache-Control
    if not cache_control:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Cache-Control Header Missing",
            severity="MEDIUM",
            category="Caching",
            description="The Cache-Control header is not present. This may result in aggressive caching of sensitive content.",
            evidence={"missing_header": "cache-control"},
            impact="Sensitive content may be cached by browsers or proxies.",
            remediation="Add Cache-Control header: Cache-Control: no-store, no-cache, must-revalidate",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
            cwe="CWE-524",
            owasp="A01:2021 Broken Access Control"
        ))
    else:
        # Analyze Cache-Control directives
        if "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower():
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Permissive Cache-Control Configuration",
                severity="MEDIUM",
                category="Caching",
                description="The Cache-Control header does not include 'no-store' or 'no-cache' directives.",
                evidence={"cache-control": cache_control},
                impact="Sensitive content may be cached.",
                remediation="Use strict caching for sensitive content: Cache-Control: no-store, no-cache, must-revalidate",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
            ))
    
    # Check for Pragma header (legacy)
    if pragma and pragma.lower() == "no-cache":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Legacy Pragma Header Used",
            severity="LOW",
            category="Caching",
            description="The 'Pragma' header is used (legacy approach). Use Cache-Control instead.",
            evidence={"pragma": pragma},
            impact="Browser compatibility may vary with legacy Pragma header.",
            remediation="Prefer Cache-Control header over Pragma for modern browsers.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma"
        ))
    
    # Check Expires header
    if expires:
        # Check if it's a far-future date (permissive caching)
        if "2030" in expires or "2040" in expires or "2050" in expires:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Far-Future Expires Header",
                severity="LOW",
                category="Caching",
                description="The Expires header is set to a far-future date, allowing long-term caching.",
                evidence={"expires": expires},
                impact="Content will be cached for an extended period.",
                remediation="Review expiration dates for sensitive resources.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires"
            ))
    
    # Positive finding
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Appropriate Cache Configuration",
            severity="INFO",
            category="Caching",
            description="Cache-related headers are appropriately configured.",
            evidence={"cache_headers_present": True},
            impact="Content caching is properly controlled.",
            remediation="Continue monitoring cache configuration.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
