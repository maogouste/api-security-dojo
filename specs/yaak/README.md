# API Security Dojo - Yaak Collection

Collection Yaak pour tester les 15 vulnérabilités (V01-V10, G01-G05).

## Installation

1. Installer [Yaak](https://yaak.app/download)
2. Ouvrir Yaak
3. Settings → Import Data → sélectionner `api-security-dojo.yaak.json`

**Alternative** : Import depuis OpenAPI
- Settings → Import Data → OpenAPI
- Sélectionner `../openapi.json`

## Environnements

Après import, 6 environnements sont disponibles :

| Environnement | URL |
|---------------|-----|
| Python/FastAPI | http://localhost:8000 |
| Node/Express | http://localhost:3001 |
| Go/Gin | http://localhost:3002 |
| PHP | http://localhost:3003 |
| Java/Spring | http://localhost:3004 |
| Rust/Actix | http://localhost:3006 |

## Utilisation

1. Sélectionner un environnement
2. Exécuter "Login" dans le dossier Auth
3. Copier le token dans la variable `token` de l'environnement
4. Tester les vulnérabilités

## Structure

```
Auth/
├── Login
├── Register
└── Get Current User (V03)

Users (V01, V03, V05)/
├── V01 BOLA - Get Admin Data
├── List Users (V03)
└── V05 Mass Assignment

Products (V06 SQLi)/
├── List Products
├── V06 SQLi - OR 1=1
└── V06 SQLi - UNION Extract Flags

Tools (V07, V08)/
├── V07 CMDi - Ping
├── V07 CMDi - DNS
└── V08 Debug Endpoint

Legacy API (V09)/
├── V09 Legacy API - List Users
└── V09 Legacy API - Get User

GraphQL (G01-G05)/
├── G01 Introspection
├── G02 Nested Query DoS
├── G03 Batching Attack
├── G04 Field Suggestions
└── G05 Authorization Bypass
```

## Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | password456 | user |
