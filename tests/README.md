# API Security Dojo Cross-Implementation Tests

Tests REST (V01-V10) and GraphQL (G01-G05) vulnerabilities across all API Security Dojo implementations.

## Tested Vulnerabilities

### REST API (V01-V10)

| ID  | Vulnerability              | OWASP       | Description                               |
|-----|---------------------------|-------------|-------------------------------------------|
| V01 | BOLA                      | API1:2023   | Access other users' data without auth     |
| V02 | Broken Authentication     | API2:2023   | User enumeration, weak passwords          |
| V03 | Excessive Data Exposure   | API3:2023   | Internal notes, supplier cost exposed     |
| V04 | Lack of Rate Limiting     | API4:2023   | No rate limit on login/API endpoints      |
| V05 | Mass Assignment           | API6:2023   | Role escalation via field injection       |
| V06 | SQL Injection             | API8:2023   | SQLi in product search                    |
| V07 | Command Injection         | API8:2023   | RCE in ping/dns tools                     |
| V08 | Security Misconfiguration | API7:2023   | CORS *, debug endpoint, missing headers   |
| V09 | Improper Assets Mgmt      | API9:2023   | Legacy API exposes password hashes        |
| V10 | Insufficient Logging      | API10:2023  | No account lockout, attacks not blocked   |

### GraphQL (G01-G05)

| ID  | Vulnerability          | Description                               |
|-----|------------------------|-------------------------------------------|
| G01 | Introspection          | Schema exposed via `__schema` query       |
| G02 | No Depth Limit         | Deep nested queries allowed (DoS vector)  |
| G03 | Batching               | Multiple queries processed without limits |
| G04 | Field Suggestions      | Error messages reveal valid field names   |
| G05 | Auth Bypass            | Sensitive data accessible without auth    |

## Backends

| Backend | Port | URL                      |
|---------|------|--------------------------|
| Python  | 3001 | http://localhost:3001    |
| Go      | 3002 | http://localhost:3002    |
| PHP     | 3003 | http://localhost:3003    |
| Java    | 3004 | http://localhost:3004    |
| Node    | 3005 | http://localhost:3005    |

## Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Or use existing venv
source ../implementations/python-fastapi/venv/bin/activate
```

## Running Tests

### Test All Backends
```bash
# Start all backends first
cd ../implementations/python-fastapi && ./start.sh &
cd ../implementations/go-gin && go run main.go &
cd ../implementations/php-laravel && php -S localhost:3003 index.php &
cd ../implementations/java-spring && mvn spring-boot:run &
cd ../implementations/node-express && npm start &

# Run all tests
pytest cross-implementation/ -v
```

### Test Specific Backend
```bash
# Using environment variable
DOJO_BACKENDS=python pytest cross-implementation/ -v
DOJO_BACKENDS=go,php pytest cross-implementation/ -v
```

### Test REST or GraphQL Only
```bash
# REST tests only (V01-V10)
pytest cross-implementation/test_rest_vulnerabilities.py -v

# GraphQL tests only (G01-G05)
pytest cross-implementation/test_graphql_vulnerabilities.py -v
```

### Test Specific Vulnerability
```bash
# Single vulnerability
pytest cross-implementation/ -v -k "V01"
pytest cross-implementation/ -v -k "V06"
pytest cross-implementation/ -v -k "G01"

# Multiple vulnerabilities
pytest cross-implementation/ -v -k "V01 or V06"
pytest cross-implementation/ -v -k "SQLi or BOLA"
```

### Combined Filters
```bash
# Test V06 (SQLi) on Go and PHP only
DOJO_BACKENDS=go,php pytest cross-implementation/ -v -k "V06"

# Test all REST vulns on Python only
DOJO_BACKENDS=python pytest cross-implementation/test_rest_vulnerabilities.py -v
```

## Test Output

Tests print vulnerability findings:
```
[python] V01 VULNERABLE: Accessed admin user data without auth
[python] V06 VULNERABLE: SQLi returned 6 products (including hidden)
[python] V07 VULNERABLE: Command injection successful
[python] V09 VULNERABLE: Legacy API exposes password hashes
```

Summary test shows all vulnerabilities at once:
```
[python] REST VULNERABILITY SUMMARY:
  V01_bola: VULNERABLE
  V02_auth: VULNERABLE
  V03_exposure: VULNERABLE
  V04_rate_limit: VULNERABLE
  V05_mass_assign: VULNERABLE
  V06_sqli: VULNERABLE
  V07_cmdi: VULNERABLE
  V08_misconfig: VULNERABLE
  V09_legacy: VULNERABLE
  V10_logging: VULNERABLE
  Total: 10/10 vulnerabilities present
```

## Test Count

| Test File                        | Tests | Per Backend | Total (5 backends) |
|----------------------------------|-------|-------------|--------------------|
| test_rest_vulnerabilities.py     | 25    | 25          | 125                |
| test_graphql_vulnerabilities.py  | 15    | 15          | 75                 |
| **Total**                        | **40**| **40**      | **200**            |

## Auto-Skip

Tests automatically skip for backends that are not running. No configuration needed.
