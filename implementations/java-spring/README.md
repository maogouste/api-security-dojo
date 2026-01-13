# API Security Dojo - Java/Spring Boot Implementation

Intentionally vulnerable API for learning API security.

## Warning

This software contains **intentional** vulnerabilities for educational purposes.
**Never deploy in production.**

## Quick Start

```bash
# Build and run with Maven
./mvnw spring-boot:run

# Or build the JAR first
./mvnw package
java -jar target/vulnapi-spring-0.2.0.jar
```

The API will be available at `http://localhost:3004`

## Requirements

- Java 17+
- Maven 3.6+

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | API information |
| `/health` | Health check |
| `/api/*` | REST API endpoints |
| `/api/v1/*` | Legacy API (V09) |
| `/graphql` | GraphQL endpoint |

## Tech Stack

- Java 17
- Spring Boot 3.2.0
- SQLite (via JDBC)
- JJWT (JSON Web Tokens)
- graphql-java

## License

Educational use only.
