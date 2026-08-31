"""Sensitive data redaction utilities."""

import re
from typing import Dict, Any


class DataRedactor:
    """Redacts sensitive data from headers and responses."""
    
    # Headers that should have values redacted
    SENSITIVE_HEADERS = {
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-forwarded-for",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "www-authenticate",
        "authentication-info",
    }
    
    # Patterns to redact
    PATTERNS = {
        "bearer_token": r"(Bearer\s+)([^\s]+)",
        "basic_auth": r"(Basic\s+)([^\s]+)",
        "api_key": r"([Aa]pi[_-]?[Kk]ey[=:]?)([^\s,;]+)",
        "jwt": r"(eyJ[\w\-\.]+)",
        "session_id": r"(JSESSIONID|PHPSESSID|SID|session_id)[=]([^\s;,]+)",
    }
    
    @staticmethod
    def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """
        Redact sensitive values from HTTP headers.
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Dictionary with sensitive values redacted
        """
        redacted = {}
        
        for key, value in headers.items():
            if key.lower() in DataRedactor.SENSITIVE_HEADERS:
                if key.lower() == "cookie" or key.lower() == "set-cookie":
                    redacted[key] = DataRedactor._redact_cookies(value)
                else:
                    redacted[key] = "[REDACTED]"
            else:
                # Check for patterns in the value
                redacted_value = DataRedactor._redact_patterns(value)
                redacted[key] = redacted_value
        
        return redacted
    
    @staticmethod
    def _redact_cookies(cookie_string: str) -> str:
        """
        Redact sensitive cookie values while preserving structure.
        
        Example:
            sessionid=abc123; Path=/; HttpOnly
            becomes:
            sessionid=[REDACTED]; Path=/; HttpOnly
        """
        parts = []
        
        for part in cookie_string.split(";"):
            part = part.strip()
            
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                
                # Keep metadata attributes as-is
                if key.lower() in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
                    parts.append(part)
                else:
                    # Redact cookie value
                    parts.append(f"{key}=[REDACTED]")
            else:
                # Keep attributes like "Secure", "HttpOnly"
                parts.append(part)
        
        return "; ".join(parts)
    
    @staticmethod
    def _redact_patterns(text: str) -> str:
        """
        Redact sensitive patterns from text.
        """
        for pattern_name, pattern in DataRedactor.PATTERNS.items():
            try:
                # For patterns with groups, replace the sensitive group
                if pattern_name in ("bearer_token", "basic_auth", "api_key"):
                    text = re.sub(pattern, r"\1[REDACTED]", text, flags=re.IGNORECASE)
                else:
                    text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
            except Exception:
                pass  # Skip invalid patterns
        
        return text
    
    @staticmethod
    def redact_response_body(text: str) -> str:
        """
        Redact sensitive data from response body.
        """
        return DataRedactor._redact_patterns(text)
    
    @staticmethod
    def is_sensitive_header(header_name: str) -> bool:
        """Check if a header is sensitive."""
        return header_name.lower() in DataRedactor.SENSITIVE_HEADERS
