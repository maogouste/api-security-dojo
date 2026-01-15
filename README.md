# API Security Dojo

Intentionally vulnerable API for learning API security. Available in 6 languages.

## Warning

This software contains **intentional** security vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Clone
git clone https://github.com/maogouste/api-security-dojo.git
cd api-security-dojo

# Install hatch (once)
pip install hatch

# Run Python backend (auto-creates venv)
cd implementations/python-fastapi
hatch run serve              # http://localhost:8000

# Or other backends:
cd implementations/node-express && npm install && npm start      # :3005
cd implementations/go-gin && go run main.go                      # :3002
cd implementations/php-laravel && php -S localhost:3003 index.php
cd implementations/java-spring && mvn spring-boot:run            # :3004
cd implementations/rust-actix && cargo run                       # :3006
```

## Implementations

| Backend | Language | Port | Framework |
|---------|----------|------|-----------|
| python-fastapi | Python | 8000 | FastAPI |
| go-gin | Go | 3002 | Gin |
| php-laravel | PHP | 3003 | Vanilla PHP |
| java-spring | Java | 3004 | Spring Boot |
| node-express | Node.js | 3005 | Express.js |
| rust-actix | Rust | 3006 | Actix-web |

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

## Development with Hatch

[Hatch](https://hatch.pypa.io/) manages Python environments automatically.

### Python Backend

```bash
cd implementations/python-fastapi

hatch run serve          # Start server on :8000
hatch run dev            # Start with auto-reload
hatch run test           # Run unit tests
hatch run test-cov       # Run tests with coverage
hatch shell              # Activate the venv
```

### Cross-Implementation Tests

```bash
# From project root
hatch run test           # All tests
hatch run rest           # REST V01-V10 tests
hatch run graphql        # GraphQL G01-G05 tests
hatch run health         # Health endpoint tests

# Test specific backend
hatch run python         # Python only
hatch run go             # Go only
hatch run rust           # Rust only

# Test specific vulnerability
hatch run v01            # BOLA tests
hatch run v06            # SQL Injection tests
hatch run g01            # GraphQL Introspection
```

## Modes

```bash
# Challenge mode (default) - find vulnerabilities yourself
DOJO_MODE=challenge hatch run serve

# Documentation mode - full exploitation details
DOJO_MODE=documentation hatch run serve
```

## Frontend

A React frontend is included for interactive exploration:

```bash
cd frontend
npm install && npm run dev
```

Access at http://localhost:3000 - includes a backend selector for all 6 implementations.

## Docker

```bash
# Run all backends
docker-compose up --build

# Services will be available on ports 8000, 3002, 3003, 3004, 3005
```

## Test with API Security Checker

Use [api-security-checker](https://github.com/maogouste/api-security-checker) to validate vulnerabilities:

```bash
# Install scanner
pip install hatch
cd /path/to/api-security-checker
hatch run apisec scan http://localhost:8000 -u john -p password123
```

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | password456 | user |

## License

MIT - Educational use only.
