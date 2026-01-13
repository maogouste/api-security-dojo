# API Security Dojo - PHP Implementation

Intentionally vulnerable API for learning API security.

## Warning

This software contains **intentional** vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Start with PHP built-in server
php -S localhost:3003 index.php
```

The API will be available at `http://localhost:3003`

## Requirements

- PHP 8.0+
- SQLite3 extension

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | API information |
| `/health` | Health check |
| `/api/*` | REST API endpoints |
| `/api/v1/*` | Legacy API (V09) |
| `/graphql/` | GraphQL endpoint (simplified) |

## Tech Stack

- PHP 8.0+ (vanilla, no framework)
- SQLite3 (native extension)
- Custom JWT implementation

## License

Educational use only.
