"""Cross-Origin Resource Sharing (CORS) analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_cors(headers: Dict[str, str]) -> List[Finding]:
    """Analyze CORS-related headers."""
    findings = []
    
    acoa = _get_header(headers, "access-control-allow-origin")
    
    if not acoa:
        # No CORS headers - could be expected for some sites
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="No CORS Headers Detected",
            severity="INFO",
            category="Cross-Origin Resource Sharing",
            description="Access-Control-Allow-Origin header is not present.",
            evidence={"missing_header": "access-control-allow-origin"},
            impact="Cross-origin requests are not explicitly allowed.",
            remediation="If cross-origin access is needed, configure appropriate CORS headers.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"
        ))
        return findings
    
    # Check if wildcard is used
    if acoa == "*":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="CORS Allow-Origin Wildcard",
            severity="MEDIUM",
            category="Cross-Origin Resource Sharing",
            description="The Access-Control-Allow-Origin header uses wildcard '*', allowing requests from any origin.",
            evidence={"access-control-allow-origin": acoa},
            impact="Any website can make cross-origin requests to this application.",
            remediation="Restrict CORS to specific trusted origins instead of using wildcard.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
            cwe="CWE-346",
            owasp="A01:2021 Broken Access Control"
        ))
    
    # Check for suspicious allow-credentials with wildcard
    acac = _get_header(headers, "access-control-allow-credentials")
    if acoa == "*" and acac and acac.lower() == "true":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Dangerous CORS Configuration",
            severity="CRITICAL",
            category="Cross-Origin Resource Sharing",
            description="Access-Control-Allow-Origin is set to '*' AND Access-Control-Allow-Credentials is 'true'. This is invalid and dangerous.",
            evidence={
                "access-control-allow-origin": acoa,
                "access-control-allow-credentials": acac
            },
            impact="Credentials can be accessed by any origin, allowing session hijacking.",
            remediation="Never use wildcard with credentials. Specify explicit origins: Access-Control-Allow-Origin: https://trusted.com",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
            cwe="CWE-346"
        ))
    
    # Check for allow-methods
    acam = _get_header(headers, "access-control-allow-methods")
    if acam and "*" in acam:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Overly Permissive CORS Methods",
            severity="MEDIUM",
            category="Cross-Origin Resource Sharing",
            description="Access-Control-Allow-Methods uses wildcard or allows too many methods.",
            evidence={"access-control-allow-methods": acam},
            impact="Unnecessary HTTP methods may be accessible to cross-origin requests.",
            remediation="Restrict to necessary methods: Access-Control-Allow-Methods: GET, POST",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"
        ))
    
    # Check for allow-headers
    acah = _get_header(headers, "access-control-allow-headers")
    if acah and "*" in acah:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Overly Permissive CORS Headers",
            severity="MEDIUM",
            category="Cross-Origin Resource Sharing",
            description="Access-Control-Allow-Headers allows all headers via wildcard.",
            evidence={"access-control-allow-headers": acah},
            impact="Any header can be sent in cross-origin requests, potentially allowing header injection.",
            remediation="Restrict to necessary headers: Access-Control-Allow-Headers: Content-Type, Accept",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers"
        ))
    
    # Check for max-age
    acma = _get_header(headers, "access-control-max-age")
    if not acma:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="CORS Cache Not Set",
            severity="LOW",
            category="Cross-Origin Resource Sharing",
            description="Access-Control-Max-Age is not configured, resulting in preflight requests for every cross-origin call.",
            evidence={"missing_header": "access-control-max-age"},
            impact="Increased latency for cross-origin requests due to repeated preflight checks.",
            remediation="Set Access-Control-Max-Age to an appropriate value: Access-Control-Max-Age: 86400",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age"
        ))
    
    # Positive finding
    if not findings or all(f.severity == "INFO" for f in findings):
        findings.insert(0, Finding(
            id=str(uuid.uuid4()),
            title="CORS Configuration Detected",
            severity="INFO",
            category="Cross-Origin Resource Sharing",
            description="CORS headers are configured and allow cross-origin requests.",
            evidence={"headers_detected": True},
            impact="Cross-origin requests are handled explicitly.",
            remediation="Ensure CORS configuration only allows trusted origins.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
