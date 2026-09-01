"""SSRF (Server-Side Request Forgery) Protection."""

import re
import socket
import ipaddress
from typing import Optional, List
from urllib.parse import urlparse
from app.config import settings


class SSRFValidator:
    """Validates URLs to prevent SSRF attacks."""
    
    # Cloud metadata endpoints to block
    BLOCKED_HOSTNAMES = {
        "169.254.169.254",  # AWS metadata
        "metadata.google.internal",  # GCP metadata
        "metadata.alibaba.internal",  # Alibaba Cloud
        "100.100.100.200",  # Alibaba Cloud IP
        "169.254.169.123",  # Azure metadata
        "localhost",
        "127.0.0.1",
        "::1",  # IPv6 loopback
    }
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),  # Loopback
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local
        ipaddress.ip_network("::1/128"),  # IPv6 loopback
        ipaddress.ip_network("fc00::/7"),  # IPv6 private
        ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ]
    
    @staticmethod
    def validate_url(url: str) -> tuple[bool, Optional[str]]:
        """
        Validate URL for SSRF safety.
        
        Returns:
            tuple: (is_safe, error_message)
        """
        # Parse URL and validate scheme
        if "://" in url:
            try:
                parsed = urlparse(url)
            except Exception as e:
                return False, f"Invalid URL: {str(e)}"
            
            # Only allow HTTP and HTTPS
            if parsed.scheme not in ("http", "https"):
                return False, "Only HTTP and HTTPS schemes are allowed"
        else:
            # Normalize schemeless URL
            url = f"https://{url}"
            try:
                parsed = urlparse(url)
            except Exception as e:
                return False, f"Invalid URL: {str(e)}"
            
            if parsed.scheme not in ("http", "https"):
                return False, "Only HTTP and HTTPS schemes are allowed"
        
        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            return False, "URL must contain a hostname"
        
        # Check against blocked hostnames
        if hostname.lower() in SSRFValidator.BLOCKED_HOSTNAMES:
            return False, f"Hostname '{hostname}' is blocked"
        
        # Check for allowlist
        allowlist = SSRFValidator._get_allowlist()
        if allowlist and hostname.lower() in allowlist:
            return True, None  # Allowlisted, pass through
        
        # Check if we should block private IPs
        if settings.ssrf_allow_private:
            return True, None  # SSRF protection disabled for internal testing
        
        # Resolve hostname to IP addresses
        try:
            resolved_ips = socket.getaddrinfo(hostname, None)
            ips = set()
            for family, type_, proto, canonname, sockaddr in resolved_ips:
                ip = sockaddr[0]
                ips.add(ip)
            
            # Check each resolved IP
            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Check if IP is in private ranges
                    for private_range in SSRFValidator.PRIVATE_RANGES:
                        if ip in private_range:
                            return False, f"Hostname '{hostname}' resolves to private IP: {ip_str}"
                except ValueError:
                    return False, f"Invalid IP address: {ip_str}"
        
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {hostname}"
        except Exception as e:
            return False, f"DNS resolution error: {str(e)}"
        
        return True, None
    
    @staticmethod
    def _get_allowlist() -> List[str]:
        """Get the SSRF allowlist from configuration."""
        if not settings.ssrf_allowlist:
            return []
        return [h.strip().lower() for h in settings.ssrf_allowlist.split(",") if h.strip()]


def validate_ssrf(url: str) -> None:
    """
    Validate URL for SSRF safety.
    
    Raises:
        ValueError: If URL fails SSRF validation
    """
    is_safe, error_message = SSRFValidator.validate_url(url)
    if not is_safe:
        raise ValueError(f"SSRF Validation Failed: {error_message}")
