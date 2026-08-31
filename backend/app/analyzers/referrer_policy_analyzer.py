"""Referrer-Policy analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_referrer_policy(headers: Dict[str, str]) -> List[Finding]:
    """Analyze Referrer-Policy header."""
    findings = []
    
    referrer_policy = _get_header(headers, "referrer-policy")
    
    if not referrer_policy:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Referrer-Policy Header Missing",
            severity="MEDIUM",
            category="Privacy",
            description="The Referrer-Policy header is not present. The browser uses default referrer behavior.",
            evidence={"missing_header": "referrer-policy"},
            impact="Referrer information may expose sensitive URLs to third-party sites.",
            remediation="Add Referrer-Policy header: Referrer-Policy: strict-origin-when-cross-origin",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ))
        return findings
    
    # Check the value
    value = referrer_policy.strip().lower()
    
    # Valid values
    valid_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
    }
    
    if value not in valid_values:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Invalid Referrer-Policy Value",
            severity="MEDIUM",
            category="Privacy",
            description=f"Referrer-Policy has invalid value: {referrer_policy}",
            evidence={"referrer-policy": referrer_policy},
            impact="Referrer policy may not be applied correctly.",
            remediation="Use valid value: strict-origin-when-cross-origin, no-referrer, or same-origin",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ))
        return findings
    
    # Check for overly permissive policies
    if value == "unsafe-url":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Overly Permissive Referrer-Policy",
            severity="HIGH",
            category="Privacy",
            description="Referrer-Policy is set to 'unsafe-url', sending full referrer to all requests.",
            evidence={"referrer-policy": referrer_policy},
            impact="Sensitive information in URLs may be exposed to third-party sites.",
            remediation="Use restrictive policy: Referrer-Policy: strict-origin-when-cross-origin",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            cwe="CWE-200",
            owasp="A01:2021 Broken Access Control"
        ))
    elif value == "no-referrer-when-downgrade":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Suboptimal Referrer-Policy",
            severity="LOW",
            category="Privacy",
            description="Referrer-Policy is set to 'no-referrer-when-downgrade'. Consider using a stricter policy.",
            evidence={"referrer-policy": referrer_policy},
            impact="Referrer may still be exposed to HTTPS sites.",
            remediation="Use stricter policy: Referrer-Policy: strict-origin-when-cross-origin",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ))
    
    # Positive finding
    if not findings or all(f.severity in ("LOW", "INFO") for f in findings):
        findings.insert(0, Finding(
            id=str(uuid.uuid4()),
            title="Referrer-Policy Configured",
            severity="INFO",
            category="Privacy",
            description="Referrer-Policy is configured to control referrer information.",
            evidence={"referrer-policy": referrer_policy},
            impact="Referrer exposure is controlled.",
            remediation="Continue monitoring referrer policy.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
