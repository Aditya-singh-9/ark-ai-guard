<div align="center">

# ⚡ ARK DevSecOps AI Guard

### Enterprise-Grade AI-Powered Security Scanning Platform

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**ARK AI Guard** is a production-grade DevSecOps platform that automatically scans GitHub repositories for security vulnerabilities, generates AI-powered remediation advice, enforces compliance standards (SOC 2, PCI DSS, HIPAA, ISO 27001), and generates hardened CI/CD pipelines — all in one unified dashboard.

[🚀 Live Demo](#) · [📖 API Docs](#api-reference) · [🐛 Report Bug](https://github.com/yourusername/ark-ai-guard/issues) · [💡 Feature Request](https://github.com/yourusername/ark-ai-guard/issues)

</div>

---

## 📸 Screenshots

| Dashboard Overview | Security Scans | Vulnerability Report |
|---|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Scans](docs/screenshots/scans.png) | ![Vulns](docs/screenshots/vulns.png) |

| Compliance Analysis | Threat Analysis | CI/CD Generator |
|---|---|---|
| ![Compliance](docs/screenshots/compliance.png) | ![Threats](docs/screenshots/threats.png) | ![CICD](docs/screenshots/cicd.png) |

---

## 🌟 Key Features

### 🔍 7-Layer Security Scanning (Nexus Engine)
| Layer | Scanner | What it Finds |
|-------|---------|---------------|
| Layer 1 | Native Surface Scanner | Hardcoded secrets, SQL injection, XSS patterns |
| Layer 2 | Semantic Analysis | Code flow vulnerabilities, auth bypass |
| Layer 3 | Cryptography | Weak algorithms (MD5, SHA1, ECB mode), bad key sizes |
| Layer 4 | Dependency Scanning | CVE database, vulnerable packages |
| Layer 5 | Data Flow | Injection paths, tainted input tracking |
| Layer 6 | IaC / Config | Misconfigured Docker, Kubernetes, Terraform |
| Layer 7 | AI Fusion | Mythos AI correlates all findings into exploitability chains |

Plus external scanners: **Semgrep**, **Bandit**, **Trivy** — all run automatically in one click.

### 🧠 Mythos AI Engine (3-Tier Reasoning)
```
Tier 1 → Mythos-7B (Offline GGUF model — local, private, no API cost)
Tier 2 → Heuristic Logic Inference (rule-based, 100% offline fallback)
Tier 3 → Google Gemini API (cloud AI for deep analysis)
```
- Auto-detects which tier to use based on available resources
- **False positive filtering** — eliminates noise before showing results
- **Exploitability scoring** — ranks what to fix first
- **OWASP Top 10, CWE, MITRE ATT&CK** full mapping
- **STRIDE threat modeling** — Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation

### 🛡️ Enterprise Security Hardening
- **JWT Revocation** — Redis-backed token denylist (real logout, not just client-side clearing)
- **User-specific Rate Limiting** — limits by `user_id` (prevents VPN/proxy bypass)
- **IDOR Prevention** — all 5 scan endpoints enforce strict ownership validation
- **Security Headers** — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP
- **Nginx Reverse Proxy** — with rate limiting zones and gzip compression
- **Startup Security Warnings** — alerts on insecure default keys

### 📋 Compliance & Policy
- **SOC 2 Type II** analysis
- **PCI DSS** compliance checking
- **HIPAA** data protection validation
- **ISO 27001** security controls
- **GDPR** data handling review
- **Policy-as-Code Gate** — PASS / WARN / FAIL for CI/CD integration

### 📦 Additional Features
- **SBOM Generation** — CycloneDX and SPDX formats via Trivy
- **GitHub Webhooks** — automatic scan on every push
- **CI/CD Pipeline Generator** — auto-generated GitHub Actions YAML for your tech stack
- **HTML Report Download** — professional security reports
- **Security Score Badge SVG** — embed in your GitHub README
- **Scan Trend Charts** — track security improvement over time
- **Slack Notifications** — webhook integration for scan alerts

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User's Browser                               │
│              React 18 + TypeScript + Vite + TanStack Query          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Nginx Reverse Proxy                               │
│         Rate Limiting · gzip · Security Headers · TLS Ready         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (Python 3.11)                     │
│                                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────────┐ │
│  │  Auth Router │  │ Scan Router  │  │     Reports Router         │ │
│  │  JWT + OAuth │  │ 7-Layer Scan │  │ SBOM · CI/CD · Badge       │ │
│  └─────────────┘  └──────────────┘  └────────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Nexus Orchestrator                        │   │
│  │  Surface → Semantic → Crypto → Deps → DataFlow → IaC → AI  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐   │
│  │ Mythos Engine│  │ Semgrep      │  │ Bandit + Trivy         │   │
│  │ Tier 1/2/3   │  │ 1000+ rules  │  │ Python + Dependencies  │   │
│  └──────────────┘  └──────────────┘  └────────────────────────┘   │
└──────────┬───────────────────────────────────┬─────────────────────┘
           │                                   │
           ▼                                   ▼
┌─────────────────────┐           ┌────────────────────────┐
│  PostgreSQL 16      │           │  Redis 7               │
│  (Neon - Cloud)     │           │  JWT Denylist + Cache  │
│  Users · Repos      │           │  (Upstash - Cloud)     │
│  Scans · Vulns      │           └────────────────────────┘
└─────────────────────┘
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/ark-ai-guard.git
cd ark-ai-guard
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys (see Configuration section below)

# Start the API server
uvicorn main:app --reload --port 8000
```

Backend runs at → **http://localhost:8000**  
API Docs → **http://localhost:8000/docs**

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend runs at → **http://localhost:5173**

### 4. (Optional) Run with Docker Compose

```bash
cd backend
docker compose up --build
```

This starts: PostgreSQL + Redis + FastAPI + Nginx all together.

---

## ⚙️ Configuration

Create `backend/.env` with the following variables:

```env
# ── Core Security (REQUIRED — change these!) ────────────────────────
SECRET_KEY=your-super-secret-jwt-key-minimum-32-characters-long
ENCRYPTION_KEY=your-32-char-fernet-key-in-base64-format

# ── GitHub OAuth (for user login) ───────────────────────────────────
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret
GITHUB_WEBHOOK_SECRET=your-webhook-secret-string

# ── AI (Google Gemini) ───────────────────────────────────────────────
GEMINI_API_KEY=your-google-ai-studio-api-key

# ── Database ─────────────────────────────────────────────────────────
DATABASE_URL=sqlite:///./ark.db                    # Development (SQLite)
# DATABASE_URL=postgresql://user:pass@host/ark_db  # Production (PostgreSQL)

# ── Redis (optional — enables distributed JWT revocation) ────────────
REDIS_URL=redis://localhost:6379/0
# REDIS_URL=redis://default:xxx@host.upstash.io:port  # Upstash free tier

# ── Application ──────────────────────────────────────────────────────
APP_ENV=development
DEBUG=true
ALLOWED_ORIGINS=http://localhost:5173
```

**To generate a secure ENCRYPTION_KEY:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## 📡 API Reference

> Full interactive docs available at `http://localhost:8000/docs` (Swagger UI)

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/auth/github` | Initiate GitHub OAuth flow |
| `GET` | `/api/v1/auth/callback` | Handle OAuth callback, return JWT |
| `GET` | `/api/v1/auth/me` | Get current authenticated user |
| `POST` | `/api/v1/auth/logout` | Revoke JWT token (server-side) |

### Repositories
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/repositories` | List all connected repositories |
| `POST` | `/api/v1/repositories` | Connect a new GitHub repository |
| `DELETE` | `/api/v1/repositories/{id}` | Remove repository |
| `GET` | `/api/v1/repositories/{id}/scans` | List scan history for repo |

### Security Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan/{repo_id}` | Trigger a full security scan |
| `GET` | `/api/v1/scan/{scan_id}/status` | Get live scan status + progress |
| `GET` | `/api/v1/scans/{scan_id}/compliance` | SOC2/PCI/HIPAA/ISO 27001 analysis |
| `GET` | `/api/v1/scans/{scan_id}/owasp` | OWASP Top 10 breakdown |
| `GET` | `/api/v1/scans/{scan_id}/threat-analysis` | STRIDE + MITRE ATT&CK |
| `GET` | `/api/v1/scans/{scan_id}/policy` | Policy-as-code gate result |
| `GET` | `/api/v1/scans/{scan_id}/autofixes` | AI-generated code fixes |
| `POST` | `/api/v1/scans/compare` | Compare two scan results |

### Reports & Export
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vulnerability-report/{scan_id}` | Full vulnerability report (JSON) |
| `GET` | `/api/v1/vulnerability-report/{scan_id}/download` | Download HTML report |
| `GET` | `/api/v1/dashboard/stats` | Aggregate dashboard statistics |
| `GET` | `/api/v1/repositories/{id}/trends` | Score trend over time |
| `GET` | `/api/v1/repositories/{id}/sbom` | Download SBOM (CycloneDX/SPDX) |
| `GET` | `/api/v1/repositories/{id}/badge` | Security score SVG badge |
| `POST` | `/api/v1/generate-cicd` | Generate GitHub Actions YAML |
| `POST` | `/api/v1/webhooks/github` | GitHub push event webhook |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Backend health check |
| `GET` | `/` | API info and feature list |
| `GET` | `/docs` | Swagger interactive API docs |

---

## 🧪 Testing

### Backend Tests (127 tests)

```bash
cd backend

# Run all tests (excluding LLM inference tests — fast)
pytest tests/ -v --ignore=tests/test_mythos_engine.py

# Run full suite including AI engine tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=app --cov-report=html

# Run a specific test file
pytest tests/test_api_integration.py -v
pytest tests/test_auth_security.py -v
```

**Test Coverage:**
| File | Tests | What It Covers |
|------|-------|----------------|
| `test_scan_service.py` | 12 | Security score calc, deduplication |
| `test_utils.py` | 9 | Config, URL validation, enums |
| `test_api_integration.py` | 63 | IDOR, auth guards, headers, system |
| `test_auth_security.py` | 18 | JWT revocation, denylist, rate limiter |
| `test_mythos_engine.py` | 42 | AI engine, FP detection, OWASP mapping |

### Frontend Tests (37 tests)

```bash
cd frontend

# Run all tests
npx vitest run

# Run in watch mode (re-runs on change)
npx vitest

# With coverage report
npx vitest run --coverage
```

**Test Coverage:**
| File | Tests | What It Covers |
|------|-------|----------------|
| `utils.test.ts` | 8 | `cn()` className merger |
| `api.test.ts` | 19 | Token management, URL builders, fetch |
| `AuthContext.test.tsx` | 14 | Login, logout, session restore |

---

## 📁 Project Structure

```
ark-ai-guard/
├── backend/                          # FastAPI Python backend
│   ├── app/
│   │   ├── api/                      # Route handlers
│   │   │   ├── auth.py               # GitHub OAuth + JWT
│   │   │   ├── scan.py               # Scan triggers + status
│   │   │   ├── reports.py            # Reports, SBOM, CI/CD, badges
│   │   │   ├── repository.py         # Repo CRUD
│   │   │   ├── webhooks.py           # GitHub webhook handler
│   │   │   └── limiter.py            # Smart rate limiter (user_id + IP)
│   │   ├── models/                   # SQLAlchemy database models
│   │   │   ├── user.py
│   │   │   ├── repository.py
│   │   │   ├── scan_report.py
│   │   │   └── vulnerability.py
│   │   ├── security/                 # Scanning engines
│   │   │   ├── token_denylist.py     # JWT revocation (Redis + in-memory)
│   │   │   ├── nexus_engine/         # 7-layer Nexus scanning engine
│   │   │   │   ├── layer1_surface.py
│   │   │   │   ├── layer2_semantic.py
│   │   │   │   ├── layer3_crypto.py
│   │   │   │   ├── layer4_deps.py
│   │   │   │   ├── layer5_dataflow.py
│   │   │   │   ├── layer6_iac.py
│   │   │   │   ├── layer7_ai_fusion.py
│   │   │   │   └── mythos_engine.py    # 3-tier AI reasoning
│   │   │   ├── semgrep_runner.py
│   │   │   ├── bandit_runner.py
│   │   │   └── trivy_runner.py
│   │   ├── services/                 # Business logic
│   │   │   ├── scan_service.py       # Scan orchestration
│   │   │   ├── cicd_generator.py     # GitHub Actions YAML generator
│   │   │   ├── policy_engine.py      # Policy-as-code evaluation
│   │   │   ├── autofix_service.py    # AI code fix generation
│   │   │   ├── ai_analysis_service.py
│   │   │   ├── github_service.py
│   │   │   └── repo_cloner.py
│   │   ├── database/
│   │   │   └── db.py                 # SQLAlchemy engine + session
│   │   └── utils/
│   │       ├── config.py             # Pydantic settings
│   │       └── logger.py             # Structured logging
│   ├── tests/                        # 127 backend tests
│   ├── nginx/
│   │   └── nginx.conf                # Production Nginx config
│   ├── main.py                       # FastAPI app factory
│   ├── Dockerfile                    # Multi-stage production image
│   ├── docker-compose.yml            # Full stack compose
│   ├── requirements.txt              # All dependencies
│   └── requirements-deploy.txt       # Cloud-safe deploy deps
│
├── frontend/                         # React TypeScript frontend
│   ├── src/
│   │   ├── pages/                    # Route-level page components
│   │   │   ├── DashboardOverview.tsx
│   │   │   ├── SecurityScansPage.tsx
│   │   │   ├── VulnerabilitiesPage.tsx
│   │   │   ├── RepositoriesPage.tsx
│   │   │   ├── CompliancePage.tsx    # SOC2/PCI/HIPAA/ISO27001
│   │   │   ├── ThreatAnalysisPage.tsx # STRIDE + MITRE ATT&CK
│   │   │   ├── PolicyPage.tsx        # Policy gate PASS/WARN/FAIL
│   │   │   ├── TrendsPage.tsx        # Score trend + SBOM download
│   │   │   ├── CICDGeneratorPage.tsx # GitHub Actions generator
│   │   │   ├── DeepScanPage.tsx      # Live scan visualization
│   │   │   ├── SettingsPage.tsx
│   │   │   └── ProfilePage.tsx
│   │   ├── components/
│   │   │   ├── dashboard/            # Dashboard UI components
│   │   │   │   ├── DashboardSidebar.tsx  # Grouped nav with live indicators
│   │   │   │   ├── TopNavbar.tsx         # Search + health badge + user menu
│   │   │   │   ├── MetricCard.tsx
│   │   │   │   ├── SecurityScoreGauge.tsx
│   │   │   │   ├── VulnerabilityChart.tsx
│   │   │   │   ├── ActivityChart.tsx
│   │   │   │   ├── RepositoryTable.tsx
│   │   │   │   └── VulnerabilityCard.tsx
│   │   │   └── landing/              # Landing page components
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx        # Global auth state + server logout
│   │   ├── hooks/
│   │   │   └── useApi.ts              # Centralized API hook
│   │   ├── lib/
│   │   │   ├── api.ts                 # Full backend API client
│   │   │   └── utils.ts               # Utility functions
│   │   └── test/                      # 37 frontend tests
│   ├── vite.config.ts                 # Vite + Vitest config
│   └── package.json
│
├── vercel.json                        # Vercel deployment config
└── README.md
```

---

## 🔐 Security Architecture

### Authentication Flow
```
User clicks "Login with GitHub"
    → GitHub OAuth 2.0
    → Backend exchanges code for GitHub token
    → Creates/updates User record
    → Issues signed JWT (HS256) with:
         - sub: user_id
         - username: github_login
         - jti: unique UUID (for revocation)
         - exp: 7 day expiry
    → Frontend stores JWT in localStorage
    → All API requests: Authorization: Bearer <token>
    → Backend: decode JWT → check denylist → load user
```

### JWT Revocation (Denylist)
```python
# On logout — token is ACTUALLY invalidated server-side
POST /api/v1/auth/logout
→ Extracts jti from token
→ Stores in Redis (with TTL matching token expiry)
→ Future requests with same token → 401 Unauthorized
```

### Rate Limiting Strategy
```
Authenticated routes:  key = "user:42"      (by user_id)
Unauthenticated routes: key = "1.2.3.4"    (by IP)

Why? A user could rotate IPs via VPN/proxy to bypass IP-based limits.
User-ID based limiting means: 1 rate limit per account, regardless of IP.
```

---

## 🌍 Deployment (Free Hosting)

| Service | Platform | Cost |
|---------|----------|------|
| Frontend | **Vercel** | Free forever |
| Backend API | **Render.com** | Free (sleeps after 15min) |
| PostgreSQL | **Neon.tech** | Free forever (512MB) |
| Redis | **Upstash.com** | Free forever (10k cmds/day) |

See the full step-by-step deployment guide: **[DEPLOYMENT.md](DEPLOYMENT.md)**

### One-line backend deploy on Render:
- Build command: `pip install -r requirements-deploy.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Root directory: `backend`

### One-line frontend deploy on Vercel:
- Framework: `Vite`
- Root directory: `frontend`
- Environment: `VITE_API_URL=https://your-render-url.onrender.com/api/v1`

---

## 🛠️ Tech Stack

### Backend
| Technology | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11 | Runtime |
| FastAPI | 0.115 | Web framework |
| SQLAlchemy | 2.0 | ORM |
| Pydantic | 2.10 | Data validation |
| PostgreSQL | 16 | Primary database |
| Redis | 7 | JWT denylist + caching |
| Alembic | 1.14 | Database migrations |
| python-jose | 3.3 | JWT generation + validation |
| SlowAPI | 0.1.9 | Rate limiting |
| GitPython | 3.1 | Repository cloning |
| Semgrep | 1.100 | Static analysis |
| Bandit | 1.8 | Python security SAST |
| Trivy | 0.57 | Dependency + container scanning |
| Google Gemini | 0.8 | Cloud AI analysis |
| Uvicorn | 0.32 | ASGI server |
| Nginx | 1.27 | Reverse proxy |

### Frontend
| Technology | Version | Purpose |
|-----------|---------|---------|
| React | 18 | UI framework |
| TypeScript | 5 | Type safety |
| Vite | 5 | Build tool |
| TanStack Query | 5 | Server state management |
| React Router | 6 | Client-side routing |
| Framer Motion | 11 | Animations |
| Recharts | 2 | Data visualization |
| Lucide React | - | Icons |
| Tailwind CSS | 3 | Utility-first CSS |
| shadcn/ui | - | UI component library |
| Sonner | - | Toast notifications |
| Vitest | 3.2 | Unit testing |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Run tests to ensure they pass: `pytest tests/ -v && npx vitest run`
4. Commit your changes: `git commit -m 'feat: add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

---

## 📊 Metrics

| Metric | Value |
|--------|-------|
| Backend test coverage | **31% (164 tests)** |
| Frontend tests | **37 tests** |
| API endpoints | **24 endpoints** |
| Scanner layers | **7 layers** |
| Compliance frameworks | **5 (SOC2, PCI, HIPAA, ISO27001, GDPR)** |
| Security score | **~94/100** |
| Build size | **~1MB (gzip: 304KB)** |

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 👤 Author

**Aditya Singh**

- GitHub: [@Aditya-singh-9](https://github.com/Aditya-singh-9)
- Project: [ark-ai-guard](https://github.com/Aditya-singh-9/ark-ai-guard)

---

<div align="center">

**Built with ❤️ for developers who take security seriously.**

*ARK DevSecOps AI — Scan. Analyze. Harden. Ship.*

</div>
