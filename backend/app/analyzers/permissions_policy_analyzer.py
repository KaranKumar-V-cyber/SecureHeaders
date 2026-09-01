"""Permissions-Policy analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_permissions_policy(headers: Dict[str, str]) -> List[Finding]:
    """Analyze Permissions-Policy and Feature-Policy headers."""
    findings = []
    
    # Check for Permissions-Policy (newer standard)
    permissions_policy = _get_header(headers, "permissions-policy")
    # Check for Feature-Policy (older standard)
    feature_policy = _get_header(headers, "feature-policy")
    
    if not permissions_policy and not feature_policy:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Permissions-Policy Header Missing",
            severity="MEDIUM",
            category="API Access Control",
            description="Permissions-Policy header is not configured. Browser features are unrestricted.",
            evidence={"missing_header": "permissions-policy"},
            impact="JavaScript can access sensitive browser features like camera, microphone, geolocation, etc.",
            remediation="Add Permissions-Policy header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            cwe="CWE-732",
            owasp="A04:2021 Insecure Design"
        ))
        return findings
    
    active_policy = permissions_policy or feature_policy
    policy_name = "Permissions-Policy" if permissions_policy else "Feature-Policy"
    
    # Parse directives
    directives = _parse_policy(active_policy)
    
    # Check for dangerous permissions
    dangerous_directives = {
        "camera": "Camera access should be restricted",
        "microphone": "Microphone access should be restricted",
        "geolocation": "Geolocation should be restricted",
        "payment": "Payment API access should be restricted",
        "usb": "USB access should be restricted",
    }
    
    for directive, description in dangerous_directives.items():
        if directive in directives:
            value = directives[directive].lower()
            if value == "*" or value == "'*'" or value == "(*)" or value == "('*')" or "http" in value:
                severity = "HIGH" if directive in ("camera", "microphone", "geolocation") else "MEDIUM"
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Overly Permissive {directive.title()} Permission",
                    severity=severity,
                    category="API Access Control",
                    description=f"The '{directive}' feature is permitted to all origins.",
                    evidence={"directive": directive, "value": value},
                    impact=f"Any embedded content can access {directive}.",
                    remediation=f"Restrict {directive}: {directive}=()",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    cwe="CWE-732"
                ))
    
    # Positive finding
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Permissions-Policy Configured",
            severity="INFO",
            category="API Access Control",
            description=f"{policy_name} header is configured to control browser features.",
            evidence={"policy": active_policy[:50] + "..." if len(active_policy) > 50 else active_policy},
            impact="Browser features are restricted appropriately.",
            remediation="Continue monitoring feature access restrictions.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _parse_policy(policy_string: str) -> Dict[str, str]:
    """Parse Permissions-Policy or Feature-Policy header into directives."""
    directives = {}
    import re
    # Split by comma or semicolon
    parts = [p.strip() for p in re.split(r"[,;]", policy_string) if p.strip()]
    for part in parts:
        if "=" in part:
            directive, value = part.split("=", 1)
            directives[directive.strip().lower()] = value.strip()
        elif " " in part:
            directive, value = part.split(" ", 1)
            directives[directive.strip().lower()] = value.strip()
        else:
            directives[part.lower()] = ""
    
    return directives
