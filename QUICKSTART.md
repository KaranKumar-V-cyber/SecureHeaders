# 🚀 HeaderSentinel Quick Start

Get HeaderSentinel running in 5 minutes!

## One-Command Setup (Docker)

```bash
cd HeaderSentinel
docker-compose up --build
```

Then open:
- 🎨 Frontend: http://localhost:3000
- 📚 API Docs: http://localhost:8000/docs

---

## Manual Setup (Local Development)

### Windows

#### 1. Setup Backend
```bash
cd backend

# Create and activate environment
python -m venv .venv
.venv\Scripts\activate

# Install and run
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload
```

#### 2. Setup Frontend (New Terminal)
```bash
cd frontend
npm install
copy .env.example .env.local
npm run dev
```

✅ **Access at http://localhost:3000**

### Linux/macOS

#### 1. Setup Backend
```bash
cd backend

# Create and activate environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install and run
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app.main:app --reload
```

#### 2. Setup Frontend (New Terminal)
```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

✅ **Access at http://localhost:3000**

---

## Using HeaderSentinel

### 1. Navigate to Analyzer Tab
   - Click "Analyzer" in sidebar

### 2. Enter Target URL
   - Example: `https://example.com`
   - Just domain is fine: `example.com`

### 3. Confirm Authorization
   - Check: "I own this target or have explicit authorization"
   - This is required by law

### 4. Click Analyze
   - Wait for scan to complete
   - View security findings

### 5. Review Results
   - See security score (0-100)
   - Read detailed findings
   - Get remediation advice
   - Check OWASP/CWE references

---

## First Test Scan

Try analyzing a test website:

```
URL: httpbin.org
Status: ✅ Works (no auth needed for testing)
```

---

## Features to Explore

✅ **Dashboard**
- Overview stats
- Recent scans
- Security findings summary

✅ **Analyzer**
- Scan any website
- Get detailed header analysis
- Security recommendations

✅ **Scan History**
- View all past scans
- Search by target
- Filter by severity

✅ **Settings**
- Configure preferences
- Manage scans
- API documentation

---

## Next Steps

### Learn the Security Headers Being Analyzed

1. **CSP** (Content-Security-Policy) - Prevent XSS
2. **HSTS** (Strict-Transport-Security) - Force HTTPS
3. **X-Frame-Options** - Prevent clickjacking
4. **X-Content-Type-Options** - Prevent MIME sniffing
5. **Referrer-Policy** - Control referrer info
6. **Permissions-Policy** - Restrict browser features
7. **CORS Headers** - Control cross-origin requests
8. **Cookie Security** - Secure, HttpOnly, SameSite flags

### Read the Full Docs

- 📖 [README.md](./README.md) - Project overview
- 🔧 [INSTALLATION.md](./INSTALLATION.md) - Detailed setup
- 🛡️ [SECURITY.md](./SECURITY.md) - Security considerations
- 🤝 [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribute code

### Stop Services

```bash
# Docker
docker-compose down

# Local
# Ctrl+C in both terminals
```

---

## Troubleshooting

### Backend won't start
```bash
# Port 8000 in use?
# Change to 8001:
python -m uvicorn app.main:app --port 8001 --reload

# Module errors?
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Frontend won't start
```bash
# Port 3000 in use?
npm run dev -- -p 3001

# API not connecting?
# Check .env.local has correct API_URL
# Verify backend is running
```

### Scan fails
```bash
# Check URL format (https://example.com)
# Verify network connection
# Check browser console for errors
# View backend logs
```

---

## Popular Test URLs

(For educational testing only - verify authorization!)

```
- https://example.com (Safe - test domain)
- https://github.com
- https://google.com
- https://httpbin.org (API testing)
```

---

## API Examples

### Analyze a Website
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "authorization_confirmed": true
  }'
```

### Get Scan Results
```bash
curl http://localhost:8000/api/v1/scans/{scan_id}
```

### List All Scans
```bash
curl http://localhost:8000/api/v1/scans
```

### Full API Documentation
→ http://localhost:8000/docs

---

## Security Reminders ⚠️

- **Only test sites you own or have permission to test**
- This tool is for analysis only (no exploitation)
- Use responsibly and legally
- Respect privacy and data protection laws

---

## Need Help?

1. Check [INSTALLATION.md](./INSTALLATION.md) for detailed setup
2. Read [README.md](./README.md) for feature documentation
3. Review [SECURITY.md](./SECURITY.md) for safety guidelines
4. Check API docs at http://localhost:8000/docs
5. Open an issue on GitHub

---

**Ready to analyze? Let's go! 🎯**

Start with the Analyzer tab and test your first website! 🚀
