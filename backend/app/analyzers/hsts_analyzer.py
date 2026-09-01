"""Strict-Transport-Security (HSTS) analyzer."""

from typing import Dict, List, Optional, Tuple
from app.schemas import Finding
import uuid
import re


def analyze_hsts(headers: Dict[str, str]) -> List[Finding]:
    """Analyze Strict-Transport-Security header."""
    findings = []
    
    hsts_header = _get_header(headers, "strict-transport-security")
    
    if not hsts_header:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Strict-Transport-Security Header Missing",
            severity="HIGH",
            category="Transport Security",
            description="The Strict-Transport-Security (HSTS) header is not present. This header enforces HTTPS connections.",
            evidence={"missing_header": "strict-transport-security"},
            impact="Website is vulnerable to SSL/TLS stripping attacks and downgrade attacks.",
            remediation="Add the HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            cwe="CWE-295",
            owasp="A02:2021 Cryptographic Failures"
        ))
        return findings
    
    # Parse HSTS header
    directives = _parse_hsts(hsts_header)
    
    # Check max-age value
    max_age = directives.get("max-age")
    if not max_age:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="HSTS Missing max-age",
            severity="HIGH",
            category="Transport Security",
            description="The HSTS header is missing the required max-age directive.",
            evidence={"hsts_header": hsts_header},
            impact="HSTS policy is invalid and not enforced.",
            remediation="Add max-age directive: max-age=31536000 (1 year recommended)",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            cwe="CWE-295"
        ))
        return findings
    
    # Check if max-age is too low
    try:
        max_age_value = int(max_age)
        if max_age_value < 31536000:  # Less than 1 year
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="HSTS max-age Too Short",
                severity="MEDIUM",
                category="Transport Security",
                description=f"The HSTS max-age value ({max_age_value} seconds) is less than 1 year.",
                evidence={"max_age": max_age_value},
                impact="HSTS protection expires quickly, reducing security.",
                remediation=f"Increase max-age to at least 31536000 (1 year). Recommended: 63072000 (2 years)",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
            ))
    except ValueError:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="HSTS Invalid max-age Value",
            severity="HIGH",
            category="Transport Security",
            description=f"The HSTS max-age value '{max_age}' is not a valid number.",
            evidence={"max_age": max_age},
            impact="HSTS policy is invalid and not enforced.",
            remediation="Use a valid integer value for max-age: max-age=31536000",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ))
        return findings
    
    # Check for includeSubDomains
    if "includesubdomains" not in directives:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="HSTS Missing includeSubDomains",
            severity="MEDIUM",
            category="Transport Security",
            description="The HSTS header does not include the 'includeSubDomains' directive.",
            evidence={"hsts_header": hsts_header},
            impact="Subdomains are not protected by HSTS policy.",
            remediation="Add includeSubDomains directive: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ))
    
    # Check for preload
    if "preload" not in directives:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="HSTS Preload Not Enabled",
            severity="LOW",
            category="Transport Security",
            description="The HSTS header does not include the 'preload' directive.",
            evidence={"hsts_header": hsts_header},
            impact="Website is not included in browser HSTS preload lists.",
            remediation="Add preload directive: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. Then submit to https://hstspreload.org/",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ))
    
    # Positive finding if well-configured
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Strict-Transport-Security Properly Configured",
            severity="INFO",
            category="Transport Security",
            description="A well-configured HSTS header is present with appropriate directives.",
            evidence={"hsts_header": hsts_header},
            impact="Website is protected against SSL/TLS downgrade attacks.",
            remediation="Monitor HSTS configuration and ensure it remains in place.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _parse_hsts(hsts_string: str) -> Dict[str, str]:
    """Parse HSTS header into directives."""
    directives = {}
    
    for part in hsts_string.split(";"):
        part = part.strip()
        if not part:
            continue
        
        if "=" in part:
            key, value = part.split("=", 1)
            directives[key.strip().lower()] = value.strip()
        else:
            directives[part.lower()] = ""
    
    return directives
