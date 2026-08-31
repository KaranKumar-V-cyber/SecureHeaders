"""X-Content-Type-Options analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_content_type(headers: Dict[str, str]) -> List[Finding]:
    """Analyze X-Content-Type-Options header."""
    findings = []
    
    x_content_type_options = _get_header(headers, "x-content-type-options")
    
    if not x_content_type_options:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="X-Content-Type-Options Header Missing",
            severity="MEDIUM",
            category="MIME Type Protection",
            description="The X-Content-Type-Options header is not present. Browsers may perform MIME-type sniffing.",
            evidence={"missing_header": "x-content-type-options"},
            impact="Browser may incorrectly interpret content types, enabling XSS attacks.",
            remediation="Add X-Content-Type-Options: nosniff",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            cwe="CWE-79",
            owasp="A07:2021 Cross-Site Scripting (XSS)"
        ))
        return findings
    
    # Check the value
    value = x_content_type_options.strip().lower()
    
    if value != "nosniff":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Invalid X-Content-Type-Options Value",
            severity="MEDIUM",
            category="MIME Type Protection",
            description=f"X-Content-Type-Options has invalid value: {x_content_type_options}",
            evidence={"x-content-type-options": x_content_type_options},
            impact="MIME-type sniffing protection is not enabled.",
            remediation="Use the correct value: X-Content-Type-Options: nosniff",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ))
        return findings
    
    # Positive finding
    findings.append(Finding(
        id=str(uuid.uuid4()),
        title="MIME Type Sniffing Protection Enabled",
        severity="INFO",
        category="MIME Type Protection",
        description="X-Content-Type-Options is set to 'nosniff', preventing MIME-type sniffing.",
        evidence={"x-content-type-options": x_content_type_options},
        impact="Browsers will not perform MIME-type sniffing, reducing XSS risk.",
        remediation="Continue enforcing X-Content-Type-Options header.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
