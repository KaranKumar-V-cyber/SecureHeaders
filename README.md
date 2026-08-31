# HeaderSentinel — Web Security Header Analyzer

A modern, professional cybersecurity application for analyzing HTTP response headers and identifying missing, weak, or potentially insecure web security configurations.

**For authorized security testing, application security assessments, bug bounty programs, CTF/lab environments, and defensive security analysis only.**

---

## Features

✅ **HTTP Response Header Analysis**
- Comprehensive security header inspection
- Redirect chain tracking
- Server information analysis
- Content-type detection

✅ **Security Header Coverage**
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- CORS configurations
- Cookie security analysis
- Cache-Control and related headers
- Cross-Origin policies

✅ **Security Scoring**
- 0-100 scale security score
- Severity-based deductions
- Detailed breakdown of findings
- Remediation recommendations

✅ **Professional Dashboard**
- Dark-themed cybersecurity UI
- Scan history and management
- Real-time analysis results
- Interactive header inspection
- Security findings summary
- Responsive design

✅ **Report Generation**
- JSON exports
- Markdown exports
- PDF reports with executive summaries
- Detailed remediation guidance

✅ **Cross-Platform Support**
- Windows 10/11
- Ubuntu, Debian, Kali Linux, Fedora
- Docker support for containerized deployment

✅ **Security-First Design**
- SSRF protection with intelligent allowlisting
- Sensitive data redaction
- Authorization confirmation before scanning
- Rate limiting and request validation
- Secure error handling

---

## Technology Stack

### Frontend
- **Next.js 14+** with App Router
- **TypeScript**
- **Tailwind CSS**
- **Responsive Component Architecture**

### Backend
- **Python 3.11+**
- **FastAPI**
- **Uvicorn**
- **SQLAlchemy ORM**
- **Pydantic** for validation
- **httpx** for HTTP requests
- **SQLite** (development) / **PostgreSQL** (production)

### Infrastructure
- **Docker & Docker Compose**
- **Cross-platform support** (Windows & Linux)

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- Docker (optional)

### Installation (Development)

#### Backend Setup
```bash
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

#### Frontend Setup
```bash
cd frontend
npm install
```

### Running Locally

#### Start Backend
```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend API: http://localhost:8000
API Docs: http://localhost:8000/docs

#### Start Frontend (New Terminal)
```bash
cd frontend
npm run dev
```

Frontend: http://localhost:3000

### Running with Docker

```bash
docker-compose up --build
```

Access at http://localhost:3000

---

## Project Structure

```
HeaderSentinel/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application
│   │   ├── api/
│   │   │   ├── routes.py           # API endpoints
│   │   │   └── models.py           # Pydantic request/response models
│   │   ├── analyzers/
│   │   │   ├── header_analyzer.py  # Core header analysis logic
│   │   │   ├── csp_analyzer.py     # CSP-specific analysis
│   │   │   ├── hsts_analyzer.py    # HSTS-specific analysis
│   │   │   └── cookie_analyzer.py  # Cookie analysis
│   │   ├── security/
│   │   │   ├── ssrf.py             # SSRF protection
│   │   │   └── redaction.py        # Sensitive data redaction
│   │   ├── services/
│   │   │   └── scan_service.py     # Business logic for scans
│   │   ├── reports/
│   │   │   ├── json_reporter.py    # JSON export
│   │   │   ├── markdown_reporter.py # Markdown export
│   │   │   └── pdf_reporter.py     # PDF export
│   │   ├── models/
│   │   │   └── scan.py             # SQLAlchemy models
│   │   ├── schemas/
│   │   │   └── scan.py             # Pydantic schemas
│   │   ├── database/
│   │   │   └── session.py          # Database configuration
│   │   └── utils/
│   │       ├── url_validator.py    # URL validation
│   │       └── logging.py          # Structured logging
│   ├── tests/
│   │   ├── test_header_analyzer.py
│   │   ├── test_ssrf_protection.py
│   │   ├── test_api_endpoints.py
│   │   └── conftest.py             # Test fixtures
│   ├── requirements.txt            # Python dependencies
│   └── .env.example                # Environment variables template
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx          # Root layout
│   │   │   ├── page.tsx            # Home page
│   │   │   ├── dashboard/
│   │   │   ├── analyzer/
│   │   │   ├── findings/
│   │   │   ├── history/
│   │   │   ├── reports/
│   │   │   └── settings/
│   │   ├── components/
│   │   │   ├── Sidebar.tsx
│   │   │   ├── Header.tsx
│   │   │   ├── AnalyzeForm.tsx
│   │   │   ├── FindingsCard.tsx
│   │   │   ├── SecurityScore.tsx
│   │   │   └── charts/
│   │   ├── services/
│   │   │   └── api.ts              # API client
│   │   ├── hooks/
│   │   │   └── useScans.ts
│   │   ├── types/
│   │   │   └── index.ts            # TypeScript types
│   │   └── styles/
│   │       └── globals.css
│   ├── public/
│   ├── package.json
│   ├── tsconfig.json
│   ├── next.config.mjs
│   ├── tailwind.config.ts
│   └── .env.example
│
├── docker-compose.yml
├── Dockerfile (Frontend)
├── Dockerfile.backend (Backend)
├── .gitignore
├── LICENSE
└── README.md
```

---

## API Documentation

### Analyze Website
**POST** `/api/v1/analyze`

Request:
```json
{
  "target": "https://example.com",
  "authorization_confirmed": true
}
```

Response:
```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "status": "completed",
  "security_score": 72,
  "findings": [...],
  "response_headers": {...},
  "redirect_count": 1,
  "response_time_ms": 245
}
```

### Get Scan
**GET** `/api/v1/scans/{scan_id}`

### List Scans
**GET** `/api/v1/scans?limit=20&offset=0&severity=HIGH&search=example.com`

### Delete Scan
**DELETE** `/api/v1/scans/{scan_id}`

### Generate Reports
- **JSON**: `GET /api/v1/reports/{scan_id}/json`
- **Markdown**: `GET /api/v1/reports/{scan_id}/markdown`
- **PDF**: `GET /api/v1/reports/{scan_id}/pdf`

### Full API documentation available at `/docs` (Swagger UI)

---

## Security Features

### SSRF Protection
- URL validation and normalization
- Private IP range blocking
- Cloud metadata endpoint blocking
- DNS resolution validation
- Redirect chain validation
- Configurable allowlist for internal testing

### Sensitive Data Protection
- Automatic redaction of authorization headers
- Session cookie value redaction
- API key redaction
- No storage of sensitive response data
- Centralized redaction system

### API Security
- Rate limiting (configurable)
- Request size limits
- Input validation and sanitization
- CORS allowlist
- Secure error handling
- Structured logging without sensitive data
- Environment-based secrets management

---

## Configuration

### Environment Variables

```bash
# Backend
DATABASE_URL=sqlite:///./scan_history.db
BACKEND_CORS_ORIGINS=http://localhost:3000
RATE_LIMIT_CALLS=100
RATE_LIMIT_PERIOD=60
SSRF_ALLOW_PRIVATE=false
SSRF_TIMEOUT=10

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000
```

See `.env.example` files for complete configuration.

---

## Testing

Run unit and integration tests:

### Backend
```bash
cd backend
pytest -v
```

### Frontend
```bash
cd frontend
npm test
```

### End-to-End
```bash
pytest tests/e2e/
```

---

## Authorization & Ethics

**HeaderSentinel is designed for authorized testing only.**

Before using this tool, ensure you:
- Have **explicit written authorization** to test the target
- Own the target domain/application
- Comply with applicable laws and regulations
- Are working in an authorized security assessment, bug bounty program, CTF, or lab environment

The application enforces authorization confirmation and is designed to be safe and non-destructive.

---

## Development

### Adding New Security Header Analyzers

1. Create a new analyzer in `backend/app/analyzers/`:
```python
# Example: x_custom_header_analyzer.py
from typing import Dict, List
from ..schemas.scan import Finding

def analyze_x_custom_header(headers: Dict[str, str]) -> List[Finding]:
    # Implement analysis logic
    return findings
```

2. Register in `header_analyzer.py`

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

## License

MIT License - See LICENSE file for details

---

## Support & Documentation

- **Issue Tracker**: GitHub Issues
- **Documentation**: See `docs/` directory
- **Security Policy**: Responsible disclosure for vulnerabilities

---

## Disclaimer

HeaderSentinel is provided as-is for authorized security testing purposes. The authors are not responsible for misuse or unauthorized access to systems. Always obtain proper authorization before security testing.

---

**Stay secure. Test responsibly. 🔒**
