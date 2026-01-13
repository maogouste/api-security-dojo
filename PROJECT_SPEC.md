# API Security Dojo - Intentionally Vulnerable API

## Project Vision

API Security Dojo is an educational platform demonstrating security bad practices in APIs. It allows learners to understand, exploit, and fix common vulnerabilities listed in the OWASP API Security Top 10.

## Educational Goals

- Illustrate API vulnerabilities in a controlled environment
- Compare attack vectors between REST and GraphQL
- Enable learning by doing (challenge mode)
- Provide detailed explanations (documentation mode)

---

## 4-Phase Architecture

### Phase 1: REST API + Challenges

**Goal**: Functional foundation with vulnerable REST endpoints

**Deliverables**:
- REST API with JWT authentication (intentionally poorly implemented)
- Database with fictional data
- Flag/challenge system
- OpenAPI documentation

**Vulnerabilities to implement**:
| ID | Vulnerability | Example Endpoint |
|----|---------------|------------------|
| V01 | Broken Object Level Authorization (BOLA) | `GET /api/users/{id}` |
| V02 | Broken Authentication | `POST /api/login` |
| V03 | Excessive Data Exposure | `GET /api/users/me` |
| V04 | Lack of Rate Limiting | `POST /api/login` |
| V05 | Mass Assignment | `PUT /api/users/me` |
| V06 | SQL Injection | `GET /api/products?search=` |
| V07 | Command Injection | `POST /api/tools/ping` |
| V08 | Security Misconfiguration | Headers, CORS |
| V09 | Improper Assets Management | `GET /api/v1/` vs `/api/v2/` |
| V10 | Insufficient Logging | Missing audit trails |

### Phase 2: GraphQL + Extended Challenges (COMPLETED)

**Goal**: Add a GraphQL layer with specific vulnerabilities

**Deliverables**:
- `/graphql/` endpoint with complete schema
- GraphQL-specific vulnerabilities
- 5 additional challenges (G01-G05)
- GraphiQL UI for interactive queries

**GraphQL-specific vulnerabilities**:
| ID | Vulnerability | Description | Endpoint |
|----|---------------|-------------|----------|
| G01 | Exposed introspection | Schema accessible via `__schema` | `/graphql/` |
| G02 | Nested queries (DoS) | Unlimited query depth | `/graphql/` |
| G03 | Batching attacks | Array of operations accepted | `/graphql/` |
| G04 | Field suggestions | Error messages reveal field names | `/graphql/` |
| G05 | Authorization bypass | Sensitive data without auth | `/graphql/` |

**Implementation details**:
- Framework: Strawberry GraphQL
- Types: UserType, ProductType, OrderType, ChallengeType
- Sensitive fields exposed: SSN, credit cards, API keys
- No query depth/complexity limits
- Batching enabled without restrictions

### Phase 3: Documentation Mode (COMPLETED)

**Goal**: Add educational explanations

**Deliverables**:
- Challenge/documentation toggle via `DOJO_MODE` environment variable
- Detailed explanations for all 15 vulnerabilities
- Vulnerable vs secure code examples
- OWASP and CWE references
- Exploitation steps and remediation advice

**Documentation endpoints**:
| Endpoint | Description |
|----------|-------------|
| `GET /api/docs/mode` | Current mode status |
| `GET /api/docs/stats` | Vulnerability statistics |
| `GET /api/docs/categories` | Categories with counts |
| `GET /api/docs/vulnerabilities` | List all (limited in challenge mode) |
| `GET /api/docs/vulnerabilities/{id}` | Full details (documentation mode only) |

**Documentation structure per vulnerability**:
```json
{
  "id": "V01",
  "name": "Broken Object Level Authorization",
  "category": "authorization",
  "severity": "high",
  "owasp": "API1:2023",
  "cwe": "CWE-639",
  "description": "...",
  "vulnerable_endpoint": "GET /api/users/{id}",
  "exploitation": {
    "steps": ["Step 1", "Step 2", "..."],
    "example_request": "...",
    "example_response": "..."
  },
  "vulnerable_code": "...",
  "secure_code": "...",
  "remediation": ["Fix 1", "Fix 2", "..."],
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."],
  "flag": "VULNAPI{...}"
}
```

### Phase 4: Introduction Frontend (COMPLETED)

**Goal**: Web interface to guide beginners

**Deliverables**:
- Dashboard with vulnerability statistics and quick start
- Challenges page with filtering by category
- Challenge detail page with exploitation steps (documentation mode)
- API Console for testing REST endpoints
- GraphQL Console for testing GraphQL queries
- Flag submission functionality

**Tech Stack**:
- React 18 with TypeScript
- Vite for build tooling
- Tailwind CSS v4 for styling
- React Router for navigation
- Axios for API calls

**Running the Frontend**:
```bash
cd implementations/python-fastapi/frontend
npm install
npm run dev  # Development at http://localhost:3000
npm run build  # Production build
```

---

## Tech Stack

### Main Implementation: Python

```
python-fastapi/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Configuration
│   ├── database.py          # DB connection
│   │
│   ├── models/              # SQLAlchemy models
│   │   ├── user.py
│   │   ├── product.py
│   │   └── order.py
│   │
│   ├── schemas/             # Pydantic schemas
│   │   └── ...
│   │
│   ├── routers/             # REST endpoints
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── products.py
│   │   └── tools.py
│   │
│   ├── graphql/             # GraphQL schema (Phase 2)
│   │   ├── schema.py
│   │   ├── queries.py
│   │   └── mutations.py
│   │
│   ├── challenges/          # Flag system
│   │   ├── flags.py
│   │   └── validator.py
│   │
│   ├── docs/                # Documentation mode (Phase 3)
│   │   └── vulnerabilities.json
│   │
│   └── vulnerabilities/     # Isolated vulnerable code
│       ├── bola.py
│       ├── sqli.py
│       └── ...
│
├── tests/
│   ├── exploits/            # Exploitation scripts
│   └── unit/
│
├── docker-compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

### Python Dependencies (Phase 1)

```
fastapi>=0.109.0
uvicorn>=0.27.0
sqlalchemy>=2.0.0
pydantic>=2.0.0
python-jose>=3.3.0          # JWT
passlib>=1.7.0              # Hashing (intentionally misused)
python-multipart>=0.0.6
```

### Additional Dependencies (Phase 2)

```
strawberry-graphql>=0.217.0  # GraphQL
```

---

## Shared API Contract

To facilitate reimplementations in other languages, an OpenAPI contract will be maintained:

```
specs/
├── openapi.yaml             # REST specification
├── graphql.schema           # GraphQL schema
├── challenges.json          # Challenge/flag definitions
├── test-suite/              # Portable exploitation tests
│   ├── test_bola.py
│   ├── test_sqli.py
│   └── ...
└── data/
    └── seed.sql             # Shared initial data
```

---

## Reimplementations

The project is designed to be reimplemented in other languages:

| Priority | Language | Framework | Status | Justification |
|----------|---------|-----------|--------|---------------|
| 1 | Python | FastAPI | Completed | Reference implementation |
| 2 | JavaScript | Express.js | Completed | Very popular, large ecosystem |
| 3 | Java | Spring Boot | Planned | Enterprise context |
| 4 | Go | Gin | Planned | Cloud-native, modern |
| 5 | PHP | Laravel | Planned | Legacy, still very present |

### Rules for reimplementations

1. **Follow the OpenAPI contract** — Same endpoints, same responses
2. **Same vulnerabilities** — Identical exploitable behavior
3. **Same flags** — Enable the same challenges
4. **Shared tests** — Pass the same exploitation test suite
5. **Similar structure** — Facilitate comparison between implementations

---

## Development Environment

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- SQLite (dev) / PostgreSQL (prod)

### Quick Start

```bash
# Clone the project
git clone <repo>
cd vulnapi

# Virtual environment
python -m venv venv
source venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Start the API
uvicorn app.main:app --reload

# Or via Docker
docker-compose up
```

### Environment Variables

```
DOJO_MODE=challenge|documentation
DOJO_DB_URL=sqlite:///./vulnapi.db
DOJO_SECRET_KEY=intentionally-weak-secret
DOJO_DEBUG=true
```

---

## Context for Claude

### For future sessions, remember:

1. **Project**: API Security Dojo - Intentionally vulnerable API for learning
2. **Current phase**: All 4 phases completed
3. **Stack**: Python/FastAPI + Strawberry GraphQL + React/Vite frontend
4. **Features**: 15 challenges, 2 modes, full-featured UI
5. **Reference file**: This document `PROJECT_SPEC.md`

### Useful commands for Claude

- "Continue API Security Dojo development phase X"
- "Add vulnerability Y to the REST API"
- "Prepare the reimplementation in [language]"
- "Generate exploitation tests for vulnerability Z"

---

## License and Disclaimer

**WARNING**: This software is designed for educational purposes only. Vulnerabilities are intentional. Never deploy in production or use against systems without authorization.

**License**: [TBD - MIT / GPL / etc.]

---

## Decision History

| Date | Decision |
|------|----------|
| 2026-01-11 | Project creation, 4-phase approach chosen |
| 2026-01-11 | Python/FastAPI as reference implementation |
| 2026-01-11 | Multi-language architecture planned from the start |
| 2026-01-11 | Phase 1 completed: REST API + 10 OWASP vulnerabilities + flag system |
| 2026-01-11 | Phase 2 completed: GraphQL API + 5 GraphQL-specific vulnerabilities (G01-G05) |
| 2026-01-11 | Phase 3 completed: Documentation mode with detailed vulnerability explanations |
| 2026-01-11 | Phase 4 completed: React/Vite frontend with dashboard, consoles, and challenges UI |
| 2026-01-11 | Express.js implementation completed: Full REST + GraphQL with all 15 vulnerabilities |
