"""Tests for SSRF protection."""

import pytest
from app.security.ssrf import SSRFValidator, validate_ssrf


class TestSSRFValidator:
    """Test SSRF validation."""

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        is_safe, error = SSRFValidator.validate_url("https://example.com")
        assert is_safe
        assert error is None

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        is_safe, error = SSRFValidator.validate_url("http://example.com")
        assert is_safe
        assert error is None

    def test_url_without_scheme(self):
        """Test URL without scheme (should add https)."""
        is_safe, error = SSRFValidator.validate_url("example.com")
        assert is_safe
        assert error is None

    def test_invalid_scheme(self):
        """Test invalid URL scheme."""
        is_safe, error = SSRFValidator.validate_url("ftp://example.com")
        assert not is_safe
        assert "Only HTTP and HTTPS" in error

    def test_localhost_blocked(self):
        """Test localhost is blocked."""
        is_safe, error = SSRFValidator.validate_url("http://localhost")
        assert not is_safe
        assert "blocked" in error.lower()

    def test_loopback_ip_blocked(self):
        """Test 127.0.0.1 is blocked."""
        is_safe, error = SSRFValidator.validate_url("http://127.0.0.1")
        assert not is_safe
        assert "private" in error.lower() or "blocked" in error.lower()

    def test_private_ip_blocked(self):
        """Test private IPs are blocked."""
        is_safe, error = SSRFValidator.validate_url("http://192.168.1.1")
        assert not is_safe
        assert "private" in error.lower()

    def test_metadata_endpoint_blocked(self):
        """Test cloud metadata endpoint is blocked."""
        is_safe, error = SSRFValidator.validate_url("http://169.254.169.254")
        assert not is_safe
        assert "blocked" in error.lower()

    def test_validate_ssrf_exception(self):
        """Test validate_ssrf raises exception for unsafe URL."""
        with pytest.raises(ValueError):
            validate_ssrf("http://localhost")

    def test_no_hostname(self):
        """Test URL without hostname."""
        is_safe, error = SSRFValidator.validate_url("http://")
        assert not is_safe
        assert "hostname" in error.lower()
