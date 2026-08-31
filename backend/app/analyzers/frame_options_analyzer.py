"""X-Frame-Options analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_frame_options(headers: Dict[str, str]) -> List[Finding]:
    """Analyze X-Frame-Options header."""
    findings = []
    
    x_frame_options = _get_header(headers, "x-frame-options")
    
    if not x_frame_options:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="X-Frame-Options Header Missing",
            severity="MEDIUM",
            category="Clickjacking Protection",
            description="The X-Frame-Options header is not present. This allows the site to be framed by other pages.",
            evidence={"missing_header": "x-frame-options"},
            impact="Website is vulnerable to clickjacking attacks.",
            remediation="Add X-Frame-Options header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            cwe="CWE-1021",
            owasp="A05:2021 Broken Access Control"
        ))
        return findings
    
    # Check the value
    value = x_frame_options.strip().upper()
    
    if value not in ("DENY", "SAMEORIGIN", "ALLOW-FROM"):
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Invalid X-Frame-Options Value",
            severity="MEDIUM",
            category="Clickjacking Protection",
            description=f"The X-Frame-Options header contains invalid value: {x_frame_options}",
            evidence={"x-frame-options": x_frame_options},
            impact="The header may not be processed correctly by browsers.",
            remediation="Use valid values: DENY, SAMEORIGIN, or ALLOW-FROM <url>",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ))
        return findings
    
    if value == "ALLOW-FROM":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="X-Frame-Options ALLOW-FROM Used",
            severity="LOW",
            category="Clickjacking Protection",
            description="X-Frame-Options: ALLOW-FROM is deprecated.",
            evidence={"x-frame-options": x_frame_options},
            impact="Browser support for ALLOW-FROM is limited.",
            remediation="Use CSP frame-ancestors directive instead: Content-Security-Policy: frame-ancestors 'self'",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ))
    
    # Positive finding
    if not findings or all(f.severity in ("LOW", "INFO") for f in findings):
        findings.insert(0, Finding(
            id=str(uuid.uuid4()),
            title="Clickjacking Protection Enabled",
            severity="INFO",
            category="Clickjacking Protection",
            description="X-Frame-Options header is configured to prevent clickjacking.",
            evidence={"x-frame-options": x_frame_options},
            impact="Website is protected against clickjacking attacks.",
            remediation="Continue enforcing X-Frame-Options header.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
