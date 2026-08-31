"""Cookie security analyzer."""

from typing import Dict, List, Optional
from app.schemas import Finding
import uuid


def analyze_cookies(headers: Dict[str, str]) -> List[Finding]:
    """Analyze Set-Cookie security attributes."""
    findings = []
    
    # Get all Set-Cookie headers
    cookies = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookies.append(value)
    
    if not cookies:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="No Cookies Detected",
            severity="INFO",
            category="Cookie Security",
            description="No Set-Cookie headers were found in the response.",
            evidence={"cookies": 0},
            impact="Session management via cookies is not present.",
            remediation="If cookies are used, ensure security attributes are set.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
        ))
        return findings
    
    # Analyze each cookie
    for idx, cookie in enumerate(cookies):
        cookie_name = _extract_cookie_name(cookie)
        attributes = _parse_cookie_attributes(cookie)
        
        # Check for Secure flag
        if not _has_attribute(attributes, "secure"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Cookie '{cookie_name}' Missing Secure Flag",
                severity="HIGH",
                category="Cookie Security",
                description=f"The cookie '{cookie_name}' is missing the 'Secure' flag.",
                evidence={"cookie_name": cookie_name, "attributes": attributes},
                impact="Cookie can be transmitted over insecure HTTP connections.",
                remediation="Add the Secure flag: Set-Cookie: name=value; Secure",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                cwe="CWE-614",
                owasp="A02:2021 Cryptographic Failures"
            ))
        
        # Check for HttpOnly flag
        if not _has_attribute(attributes, "httponly"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                severity="HIGH",
                category="Cookie Security",
                description=f"The cookie '{cookie_name}' is missing the 'HttpOnly' flag.",
                evidence={"cookie_name": cookie_name, "attributes": attributes},
                impact="Cookie can be accessed by JavaScript, increasing XSS vulnerability.",
                remediation="Add the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                cwe="CWE-79",
                owasp="A07:2021 Cross-Site Scripting (XSS)"
            ))
        
        # Check for SameSite
        samesite = _get_attribute_value(attributes, "samesite")
        if not samesite:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Cookie '{cookie_name}' Missing SameSite",
                severity="MEDIUM",
                category="Cookie Security",
                description=f"The cookie '{cookie_name}' is missing the 'SameSite' attribute.",
                evidence={"cookie_name": cookie_name},
                impact="Cookie is vulnerable to CSRF attacks.",
                remediation="Add SameSite attribute: Set-Cookie: name=value; SameSite=Strict or SameSite=Lax",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                cwe="CWE-352",
                owasp="A01:2021 Broken Access Control"
            ))
        elif samesite.lower() == "none":
            # SameSite=None requires Secure
            if not _has_attribute(attributes, "secure"):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Cookie '{cookie_name}' SameSite=None Without Secure",
                    severity="HIGH",
                    category="Cookie Security",
                    description=f"Cookie '{cookie_name}' has SameSite=None but missing Secure flag.",
                    evidence={"cookie_name": cookie_name, "samesite": samesite},
                    impact="SameSite=None requires Secure flag for security.",
                    remediation="Add Secure flag: Set-Cookie: name=value; SameSite=None; Secure",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                ))
    
    # Positive finding if no issues
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            title="Secure Cookie Configuration",
            severity="INFO",
            category="Cookie Security",
            description="Cookies are configured with appropriate security attributes.",
            evidence={"cookies_analyzed": len(cookies)},
            impact="Cookies are protected with Secure, HttpOnly, and SameSite flags.",
            remediation="Continue monitoring cookie configuration.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
        ))
    
    return findings


def _extract_cookie_name(cookie_string: str) -> str:
    """Extract cookie name from Set-Cookie header."""
    parts = cookie_string.split(";")
    if parts:
        cookie_part = parts[0].strip()
        if "=" in cookie_part:
            return cookie_part.split("=", 1)[0]
    return "Unknown"


def _parse_cookie_attributes(cookie_string: str) -> Dict[str, Optional[str]]:
    """Parse cookie attributes from Set-Cookie header."""
    attributes = {}
    parts = cookie_string.split(";")
    
    for idx, part in enumerate(parts):
        if idx == 0:
            continue  # Skip name=value part
        
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.strip().lower()] = None
    
    return attributes


def _has_attribute(attributes: Dict[str, Optional[str]], name: str) -> bool:
    """Check if an attribute exists."""
    return name.lower() in attributes


def _get_attribute_value(attributes: Dict[str, Optional[str]], name: str) -> Optional[str]:
    """Get attribute value."""
    return attributes.get(name.lower())
