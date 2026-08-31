# HeaderSentinel Installation & Setup Guide

## Prerequisites

### System Requirements
- **OS**: Windows 10/11, Ubuntu, Debian, Kali Linux, Fedora
- **Python**: 3.11+ (for backend)
- **Node.js**: 18+ & npm (for frontend)
- **Git**: For version control
- **Docker** (optional): For containerized deployment

### Installing Prerequisites

#### Windows
1. **Python**: Download from https://www.python.org/downloads/ (Python 3.11+)
   - Check "Add Python to PATH" during installation
2. **Node.js**: Download from https://nodejs.org/ (LTS version)
3. **Git**: Download from https://git-scm.com/download/win

#### Linux (Ubuntu/Debian)
```bash
# Update package manager
sudo apt update

# Install Python and dependencies
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install Git
sudo apt install -y git
```

#### Kali Linux / Fedora
```bash
# Kali Linux
sudo apt install -y python3.11 python3.11-venv nodejs npm git

# Fedora
sudo dnf install -y python3.11 python3.11-devel nodejs npm git
```

---

## Installation Methods

### Method 1: Local Development (Recommended for Development)

#### Step 1: Clone or Download the Project
```bash
# If using Git
git clone <repository-url> HeaderSentinel
cd HeaderSentinel

# Or download and extract the ZIP file
cd HeaderSentinel
```

#### Step 2: Setup Backend

**Windows:**
```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
copy .env.example .env

# Initialize database
python -c "from app.database import init_db; init_db()"

# Run backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Linux/macOS:**
```bash
cd backend

# Create virtual environment
python3.11 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Initialize database
python -c "from app.database import init_db; init_db()"

# Run backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend is now running at: http://localhost:8000
API Documentation: http://localhost:8000/docs

#### Step 3: Setup Frontend (New Terminal)

**Windows:**
```bash
cd frontend

# Install dependencies
npm install

# Create .env file
copy .env.example .env.local

# Run frontend
npm run dev
```

**Linux/macOS:**
```bash
cd frontend

# Install dependencies
npm install

# Create .env file
cp .env.example .env.local

# Run frontend
npm run dev
```

Frontend is now running at: http://localhost:3000

---

### Method 2: Docker Deployment

#### Prerequisites
- Docker: https://docs.docker.com/get-docker/
- Docker Compose: https://docs.docker.com/compose/install/

#### Quick Start
```bash
# From project root
docker-compose up --build

# Containers will start:
# - Backend: http://localhost:8000
# - Frontend: http://localhost:3000
```

#### Stopping Containers
```bash
docker-compose down
```

#### Accessing Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
```

---

### Method 3: Production Deployment with PostgreSQL

#### Step 1: Setup PostgreSQL

**Windows (Using WSL2 or PostgreSQL installer):**
```bash
# Create database
createdb headerssentinel

# Get connection string
# Format: postgresql://username:password@localhost/headerssentinel
```

**Linux:**
```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Start service
sudo systemctl start postgresql

# Create database
sudo -u postgres createdb headerssentinel
sudo -u postgres createuser headersent
sudo -u postgres psql -c "ALTER USER headersent WITH PASSWORD 'securepassword';"
```

#### Step 2: Configure Backend

Create `.env` file in `backend/`:
```bash
DATABASE_URL=postgresql://headersent:securepassword@localhost/headerssentinel
BACKEND_CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
SECRET_KEY=your-secure-secret-key-here
LOG_LEVEL=INFO
SSRF_ALLOW_PRIVATE=false
```

#### Step 3: Run Backend
```bash
cd backend
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### Step 4: Deploy Frontend

**Using Vercel (Recommended):**
```bash
# Install Vercel CLI
npm install -g vercel

cd frontend

# Deploy
vercel

# Set environment variables in Vercel dashboard
# NEXT_PUBLIC_API_URL=https://your-api-domain.com
```

**Using a VPS/Cloud Server:**
```bash
cd frontend

# Build production version
npm run build

# Use PM2 for process management
npm install -g pm2

# Start with PM2
pm2 start "npm start" --name "headerssentinel-frontend"
```

---

## Environment Configuration

### Backend Configuration (.env)

```bash
# Database
DATABASE_URL=sqlite:///./scan_history.db
# or for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/dbname

# API
API_TITLE=HeaderSentinel API
API_VERSION=1.0.0

# CORS Origins (comma-separated)
BACKEND_CORS_ORIGINS=http://localhost:3000

# SSRF Protection
SSRF_ALLOW_PRIVATE=false          # Set to true only for internal testing
SSRF_TIMEOUT=10                    # Request timeout in seconds
SSRF_MAX_REDIRECTS=5               # Maximum redirects to follow
SSRF_ALLOWLIST=                    # Internal targets (comma-separated)

# Security
SECRET_KEY=change-this-in-production

# Logging
LOG_LEVEL=INFO
```

### Frontend Configuration (.env.local)

```bash
# Backend API URL
NEXT_PUBLIC_API_URL=http://localhost:8000
# or for production:
# NEXT_PUBLIC_API_URL=https://api.headersent.com
```

---

## Verification

### Test Backend API
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Expected response:
# {"status":"healthy","version":"1.0.0","database":"connected"}

# Swagger UI
# Open: http://localhost:8000/docs
```

### Test Frontend
```bash
# Open browser
# http://localhost:3000

# Should see the HeaderSentinel dashboard
```

### Run Tests
```bash
cd backend

# Install test dependencies
pip install -r requirements.txt  # Already includes pytest

# Run tests
pytest -v

# Run specific test file
pytest tests/test_ssrf_protection.py -v

# Run with coverage
pytest --cov=app tests/
```

---

## Troubleshooting

### Backend Issues

**Port 8000 already in use:**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux
lsof -i :8000
kill -9 <PID>

# Use different port
python -m uvicorn app.main:app --port 8001
```

**Database connection error:**
```bash
# Check DATABASE_URL in .env
# Verify database exists
# Clear old database: rm scan_history.db (SQLite)
```

**Module import errors:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Verify Python path
python -c "import app; print(app.__file__)"
```

### Frontend Issues

**Port 3000 already in use:**
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Linux
lsof -i :3000
kill -9 <PID>

# Use different port
npm run dev -- -p 3001
```

**API connection errors:**
- Verify backend is running
- Check NEXT_PUBLIC_API_URL in .env.local
- Check browser console for errors

**Build errors:**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Docker Issues

**Container fails to start:**
```bash
# Check logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild images
docker-compose down
docker-compose up --build --force-recreate
```

**Port conflicts:**
```bash
# Use custom ports in docker-compose.yml
# Change "8000:8000" to "8001:8000"
```

---

## Security Best Practices

### Development
1. Never commit `.env` files with secrets
2. Use strong SECRET_KEY in production
3. Keep dependencies updated: `pip list --outdated`

### Production
1. Enable HTTPS only
2. Set BACKEND_CORS_ORIGINS to specific domains only
3. Use PostgreSQL instead of SQLite
4. Enable firewall rules
5. Regular backups of database
6. Monitor logs for suspicious activity
7. Keep system and dependencies updated

### SSRF Protection
- SSRF_ALLOW_PRIVATE=false by default
- For internal testing, use SSRF_ALLOWLIST instead of disabling protection
- Regularly audit target restrictions

---

## Performance Optimization

### Backend
- Use PostgreSQL for production (not SQLite)
- Enable connection pooling
- Add caching headers for responses
- Monitor with APM tools

### Frontend
- Use production build: `npm run build && npm start`
- Enable compression
- Use CDN for static assets
- Monitor Core Web Vitals

---

## Updating

### Update Dependencies
```bash
# Backend
cd backend
source .venv/bin/activate
pip install --upgrade -r requirements.txt

# Frontend
cd frontend
npm update
```

### Pull Latest Changes
```bash
git pull origin main
```

---

## Support & Documentation

- **API Docs**: http://localhost:8000/docs (Swagger UI)
- **GitHub**: [Project Repository]
- **Issues**: Report via GitHub Issues
- **Security**: Responsible disclosure policy

---

## Uninstallation

### Local Development
```bash
# Remove virtual environment
rm -rf backend/.venv  # Linux/macOS
rmdir /s backend\.venv  # Windows

# Remove node modules
rm -rf frontend/node_modules  # Linux/macOS
rmdir /s frontend\node_modules  # Windows

# Remove database
rm backend/scan_history.db  # Linux/macOS
del backend\scan_history.db  # Windows
```

### Docker
```bash
# Remove containers and volumes
docker-compose down -v
```

---

**Happy testing! Remember to always obtain proper authorization before security testing.** 🔒
