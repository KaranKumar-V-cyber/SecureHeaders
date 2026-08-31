# Security Policy

## Purpose

HeaderSentinel is designed for **authorized security testing only**. This document outlines the security considerations and responsible use of this tool.

## Authorized Use

HeaderSentinel should only be used to analyze websites where you:

1. **Own the target** - You own the domain/application
2. **Have explicit written authorization** - From the system owner/administrator
3. **Comply with legal requirements**:
   - Your country's computer fraud and abuse laws
   - OWASP ethical guidelines
   - Bug bounty program rules (if applicable)
   - CTF/Lab environment rules (if applicable)

## Responsible Disclosure

If you discover a security vulnerability in HeaderSentinel itself:

1. **Do NOT** create a public GitHub issue
2. **Email** security@headersent.com with:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

3. **Allow** 90 days for response and patching
4. **Receive** credit in security advisory (if desired)

## Security Features

### SSRF Protection (Server-Side Request Forgery)

HeaderSentinel implements multiple layers of SSRF protection:

- ✅ URL validation and normalization
- ✅ Private IP range blocking (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- ✅ Loopback address blocking (127.0.0.1, ::1)
- ✅ Cloud metadata endpoint blocking (169.254.169.254, etc.)
- ✅ Link-local address blocking (169.254.0.0/16)
- ✅ DNS rebinding protection
- ✅ Redirect chain validation
- ✅ Request timeout enforcement
- ✅ Response size limits

**Configuration:**
```bash
SSRF_ALLOW_PRIVATE=false       # Block private IPs by default
SSRF_TIMEOUT=10                # 10 second timeout
SSRF_MAX_REDIRECTS=5           # Limit redirect following
SSRF_ALLOWLIST=               # Comma-separated internal hosts (if needed)
```

**For Internal Testing:**
```bash
# Only in development/lab environments
SSRF_ALLOW_PRIVATE=true
# OR use allowlist for specific hosts
SSRF_ALLOWLIST=internal.example.com,10.0.0.5
```

### Sensitive Data Redaction

Headers containing sensitive data are automatically redacted:

**Redacted Headers:**
- `Authorization`
- `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`
- `Cookie`, `Set-Cookie`
- `Proxy-Authorization`
- `WWW-Authenticate`

**Redaction Examples:**
```
Original:  Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Redacted:  Authorization: Bearer [REDACTED]

Original:  Set-Cookie: sessionid=abc123def456; Path=/; HttpOnly
Redacted:  Set-Cookie: sessionid=[REDACTED]; Path=/; HttpOnly
```

### Input Validation

All user inputs are validated:

- URL format validation
- Hostname verification
- Scheme validation (HTTP/HTTPS only)
- Request size limits
- Rate limiting (configurable)

## Database Security

### Development (SQLite)
- Local file storage
- No network exposure
- Suitable for development only

### Production (PostgreSQL)
```bash
# Use strong credentials
DATABASE_URL=postgresql://secure_user:strong_password@db_server:5432/headersent

# Connection pooling with minimum privileges
# Regular backups
# Encryption at rest (database configuration)
# Encryption in transit (SSL/TLS)
```

## API Security

### Authentication & Authorization
Currently uses authorization confirmation for legal compliance.

**For future versions:**
- API key authentication
- User accounts with role-based access
- Audit logging

### Rate Limiting
```bash
RATE_LIMIT_CALLS=100          # 100 requests
RATE_LIMIT_PERIOD=60          # Per 60 seconds
```

### CORS Configuration
```bash
# Only allow trusted frontend origins
BACKEND_CORS_ORIGINS=https://yourdomain.com

# Avoid wildcard (*) in production
```

## Deployment Security

### Frontend
- HTTPS only in production
- Secure headers:
  - `Content-Security-Policy`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security`

### Backend
- Environment variables for secrets
- No hardcoded credentials
- Structured logging (no sensitive data)
- Regular dependency updates
- Security headers on all responses

### Infrastructure
- Firewall rules for ports 3000 (frontend) and 8000 (backend)
- HTTPS/TLS certificates
- Regular security patches
- Intrusion detection
- Access logs and monitoring

## Dependency Management

### Regular Updates
```bash
# Check for outdated packages
pip list --outdated
npm outdated

# Update safely
pip install --upgrade -r requirements.txt
npm update
```

### Vulnerability Scanning
```bash
# Backend
pip install safety
safety check

# Frontend
npm audit
npm audit fix
```

## Logging & Monitoring

### What We Log
- Scan requests and results
- API errors
- System events
- Access patterns

### What We DON'T Log
- Authorization headers
- Session cookies
- API keys or tokens
- Passwords or secrets
- Full request/response bodies containing sensitive data

### Monitoring Recommendations
- Set up alerts for:
  - Failed SSRF validations
  - Unusual API access patterns
  - Database errors
  - High response times

## Testing Security

### No Real-World Testing
- Automated tests use mock data
- Do not target real systems during test runs
- Lab/controlled environments only

### Test Targets
```python
# Mock data for testing
MOCK_HEADERS = {
    "content-type": "text/html",
    "cache-control": "no-cache"
}
```

## Compliance

### Standards
- OWASP Top 10 considerations
- CWE (Common Weakness Enumeration) references
- Security best practices

### Certifications
- No formal certification required
- Follows industry security guidelines

## Known Limitations

1. **Analysis Only**: Tool does not exploit vulnerabilities
2. **HTTP Headers Only**: Analyzes only HTTP response headers
3. **Client-Side Rendering**: Cannot test client-side-only security issues
4. **No Authentication Testing**: Does not attempt auth bypass
5. **No DoS Testing**: Cannot perform denial-of-service tests

## Incident Response

If HeaderSentinel is misused for unauthorized testing:

1. **Report to us**: security@headersent.com
2. **Include**: Target, time, details
3. **We will**:
   - Investigate
   - Coordinate with affected parties
   - Take appropriate action

## Legal Disclaimer

```
HeaderSentinel is provided "as-is" for authorized security testing.

DISCLAIMER: Users are solely responsible for ensuring they have proper 
authorization before using this tool. Unauthorized access to computer 
systems is illegal. The authors of HeaderSentinel are not responsible 
for misuse or illegal use of this tool.

By using HeaderSentinel, you agree to:
- Use only on systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Not use for malicious purposes
- Report vulnerabilities responsibly
```

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Bug Bounty Platforms](https://bugcrowd.com), [HackerOne](https://hackerone.com)

## Security Contacts

- **Email**: security@headersent.com
- **GitHub**: Security advisory for critical issues
- **Response Time**: 72 hours for initial response

---

**Version**: 1.0.0  
**Last Updated**: 2024  
**Status**: Active

Stay safe. Test responsibly. 🔐
