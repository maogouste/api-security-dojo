# API Security Dojo - Go/Gin Implementation

Intentionally vulnerable API for learning API security.

## Warning

This software contains **intentional** vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Download dependencies
go mod tidy

# Run the server
go run main.go
```

The API will be available at `http://localhost:3002`

## Build

```bash
go build -o vulnapi main.go
./vulnapi
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | API information |
| `/health` | Health check |
| `/api/*` | REST API endpoints |
| `/api/v1/*` | Legacy API (V09) |
| `/graphql/` | GraphQL endpoint + GraphiQL UI |

## Tech Stack

- Go 1.21+
- Gin web framework
- go-sqlite3 (SQLite)
- golang-jwt/jwt (JWT)
- graphql-go (GraphQL)

## License

Educational use only.
