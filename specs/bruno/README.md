# API Security Dojo - Bruno Collection

Collection Bruno pour tester les 15 vulnérabilités (V01-V10, G01-G05).

## Installation

1. Installer [Bruno](https://www.usebruno.com/downloads)
2. Ouvrir Bruno
3. File → Open Collection → sélectionner ce dossier `specs/bruno/`

## Structure

```
bruno/
├── environments/      # 6 backends (Python, Node, Go, PHP, Java, Rust)
├── auth/              # Login, Register, Me
├── users/             # V01 BOLA, V05 Mass Assignment
├── products/          # V06 SQL Injection
├── tools/             # V07 Command Injection, V08 Debug
├── legacy/            # V09 Legacy API
└── graphql/           # G01-G05 GraphQL vulns
```

## Utilisation

1. Sélectionner un environnement (ex: Python)
2. Exécuter "Login" pour obtenir un token
3. Tester les vulnérabilités

## Vulnérabilités

| Fichier | Vuln | Description |
|---------|------|-------------|
| auth/login.bru | V02 | Broken Auth - weak JWT |
| auth/me.bru | V03 | Excessive Data Exposure |
| users/V01-bola-get-admin.bru | V01 | BOLA - accès données admin |
| users/V05-mass-assignment.bru | V05 | Escalade privilèges |
| products/V06-sqli-*.bru | V06 | SQL Injection |
| tools/V07-cmdi-*.bru | V07 | Command Injection |
| tools/V08-debug-endpoint.bru | V08 | Debug exposé |
| legacy/V09-*.bru | V09 | Legacy API sans auth |
| graphql/G01-G05*.bru | G01-G05 | GraphQL vulns |

## Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | password456 | user |
