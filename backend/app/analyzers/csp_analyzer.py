"""Content Security Policy (CSP) analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_csp(headers: Dict[str, str]) -> List[Finding]:
    """Analyze Content-Security-Policy header."""
    findings = []
    
    csp_header = _get_header(headers, "content-security-policy")
    csp_report_only = _get_header(headers, "content-security-policy-report-only")
    
    if not csp_header and not csp_report_only:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Content-Security-Policy Header Missing",
            severity="HIGH",
            category="Content Security",
            description="The Content-Security-Policy header is not present. This header helps prevent cross-site scripting (XSS) and other injection attacks.",
            evidence={"missing_header": "content-security-policy"},
            impact="Website is vulnerable to XSS attacks and injection attacks.",
            remediation="Implement a strict CSP header with appropriate directives. Example: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            cwe="CWE-79",
            owasp="A7:2021 Cross-Site Scripting (XSS)"
        ))
        return findings
    
    active_csp = csp_header or csp_report_only
    directives = _parse_csp(active_csp)
    
    # Check for 'unsafe-inline'
    unsafe_inline_directives = []
    for directive, value in directives.items():
        if "'unsafe-inline'" in value.lower():
            unsafe_inline_directives.append(directive)
    
    if unsafe_inline_directives:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="CSP Contains 'unsafe-inline'",
            severity="MEDIUM",
            category="Content Security",
            description=f"The CSP header contains 'unsafe-inline' in {', '.join(unsafe_inline_directives)} directive(s). This reduces the effectiveness of CSP protection.",
            evidence={"directives": unsafe_inline_directives},
            impact="Reduces CSP protection against inline script/style injection attacks.",
            remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts/styles.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            cwe="CWE-79"
        ))
    
    # Check for 'unsafe-eval'
    unsafe_eval_directives = []
    for directive, value in directives.items():
        if "'unsafe-eval'" in value.lower():
            unsafe_eval_directives.append(directive)
    
    if unsafe_eval_directives:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="CSP Contains 'unsafe-eval'",
            severity="MEDIUM",
            category="Content Security",
            description=f"The CSP header contains 'unsafe-eval' in {', '.join(unsafe_eval_directives)} directive(s).",
            evidence={"directives": unsafe_eval_directives},
            impact="Allows evaluation of strings as code, increasing XSS vulnerability.",
            remediation="Remove 'unsafe-eval' and use alternative approaches like Web Workers.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            cwe="CWE-95"
        ))
    
    # Check for missing important directives
    if "default-src" not in directives:
        important_directives = ["script-src", "style-src", "img-src"]
        missing = [d for d in important_directives if d not in directives]
        if missing:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="CSP Missing Important Directives",
                severity="LOW",
                category="Content Security",
                description=f"The CSP header is missing 'default-src' and specific directives: {', '.join(missing)}",
                evidence={"missing_directives": ["default-src"] + missing},
                impact="Incomplete CSP policy may not provide full protection.",
                remediation="Add 'default-src' fallback directive: default-src 'self'",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
            ))
    
    # Check for overly permissive default-src
    if "default-src" in directives:
        default_src = directives["default-src"].lower()
        if "*" in default_src:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Overly Permissive CSP default-src",
                severity="MEDIUM",
                category="Content Security",
                description="The CSP default-src directive is overly permissive or uses wildcard '*'.",
                evidence={"default_src": directives["default-src"]},
                impact="Reduces CSP effectiveness in preventing resource injection attacks.",
                remediation="Restrict default-src to specific trusted sources: default-src 'self'",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
            ))
    
    # Info: CSP is present (positive finding)
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Strict Content-Security-Policy Configured",
            severity="INFO",
            category="Content Security",
            description="A well-configured Content-Security-Policy header is present.",
            evidence={"csp": active_csp[:100] + "..." if len(active_csp) > 100 else active_csp},
            impact="Website is protected against XSS and injection attacks.",
            remediation="Continue monitoring and updating CSP directives as needed.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
        ))
    
    return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _parse_csp(csp_string: str) -> Dict[str, str]:
    """Parse CSP header into directives."""
    directives = {}
    
    for part in csp_string.split(";"):
        part = part.strip()
        if not part:
            continue
        
        if " " in part:
            directive, value = part.split(" ", 1)
            directives[directive.lower()] = value.strip()
        else:
            directives[part.lower()] = ""
    
    return directives
