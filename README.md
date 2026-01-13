# VulnAPI

Intentionally vulnerable API for learning API security. Available in 5 languages.

## Warning

This software contains **intentional** security vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Clone
git clone https://github.com/maogouste/vulnapi.git
cd vulnapi

# Pick your backend
cd implementations/python-fastapi && pip install -r requirements.txt && uvicorn app.main:app
# or
cd implementations/node-express && npm install && npm start
# or
cd implementations/go-gin && go run main.go
# or
cd implementations/php-laravel && php -S localhost:3003 index.php
# or
cd implementations/java-spring && mvn spring-boot:run
```

## Implementations

| Backend | Language | Port | Framework |
|---------|----------|------|-----------|
| python-fastapi | Python | 3001 | FastAPI |
| go-gin | Go | 3002 | Gin |
| php-laravel | PHP | 3003 | Vanilla PHP |
| java-spring | Java | 3004 | Spring Boot |
| node-express | Node.js | 3005 | Express.js |

All implementations share:
- Same vulnerabilities (V01-V10, G01-G05)
- Same database schema
- Same API endpoints
- Same flags for CTF-style challenges

## Vulnerabilities

### REST API (V01-V10)

| ID | Name | OWASP |
|----|------|-------|
| V01 | Broken Object Level Authorization | API1:2023 |
| V02 | Broken Authentication | API2:2023 |
| V03 | Excessive Data Exposure | API3:2023 |
| V04 | Lack of Rate Limiting | API4:2023 |
| V05 | Mass Assignment | API6:2023 |
| V06 | SQL Injection | API8:2023 |
| V07 | Command Injection | API8:2023 |
| V08 | Security Misconfiguration | API7:2023 |
| V09 | Improper Assets Management | API9:2023 |
| V10 | Insufficient Logging | API10:2023 |

### GraphQL (G01-G05)

| ID | Name |
|----|------|
| G01 | Introspection Exposed |
| G02 | Nested Queries (DoS) |
| G03 | Batching Attacks |
| G04 | Field Suggestions |
| G05 | Authorization Bypass |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | API info |
| `/health` | Health check |
| `/docs` | Swagger UI (FastAPI only) |
| `/api/login` | Authentication |
| `/api/users` | User management |
| `/api/products` | Product catalog |
| `/api/tools/ping` | Network tools |
| `/api/v1/*` | Legacy API (V09) |
| `/graphql` | GraphQL endpoint |

## Modes

```bash
# Challenge mode (default) - find vulnerabilities yourself
VULNAPI_MODE=challenge uvicorn app.main:app

# Documentation mode - full exploitation details
VULNAPI_MODE=documentation uvicorn app.main:app
```

## Frontend

A React frontend is included for interactive exploration:

```bash
cd implementations/python-fastapi/frontend
npm install && npm run dev
```

Access at http://localhost:3000 - includes a backend selector for all 5 implementations.

## Testing

Cross-implementation tests verify GraphQL vulnerabilities (G01-G05) across all backends:

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests (start backends first)
cd tests
pytest cross-implementation/ -v

# Test specific backend
VULNAPI_BACKENDS=python pytest cross-implementation/ -v
VULNAPI_BACKENDS=go,php pytest cross-implementation/ -v

# Test specific vulnerability
pytest cross-implementation/ -v -k "G01"
```

Tests auto-skip when backend is not running.

## Docker

```bash
# Run all backends
docker-compose up --build

# Services will be available on ports 3001, 3002, 3003, 3004, 3005
```

## Test with API Security Checker

Use [api-security-checker](https://github.com/maogouste/api-security-checker) to validate vulnerabilities:

```bash
# Install scanner
pip install git+https://github.com/maogouste/api-security-checker.git

# Scan VulnAPI
apisec vulnapi                    # FastAPI
apisec vulnapi --backend express  # Express.js
apisec vulnapi --backend go       # Go
apisec vulnapi --backend php      # PHP
apisec vulnapi --backend java     # Java
```

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | password456 | user |

## License

MIT - Educational use only.
