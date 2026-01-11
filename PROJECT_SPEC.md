# VulnAPI - API Volontairement Vulnérable

## Vision du Projet

VulnAPI est une plateforme pédagogique démontrant les mauvaises pratiques de sécurité dans les APIs. Elle permet aux apprenants de comprendre, exploiter et corriger les vulnérabilités courantes listées dans l'OWASP API Security Top 10.

## Objectifs Pédagogiques

- Illustrer les vulnérabilités API dans un environnement contrôlé
- Comparer les vecteurs d'attaque entre REST et GraphQL
- Permettre l'apprentissage par la pratique (mode challenge)
- Fournir des explications détaillées (mode documentation)

---

## Architecture en 4 Phases

### Phase 1 : API REST + Challenges

**Objectif** : Socle fonctionnel avec endpoints REST vulnérables

**Livrables** :
- API REST avec authentification JWT (volontairement mal implémentée)
- Base de données avec données fictives
- Système de flags/challenges
- Documentation OpenAPI

**Vulnérabilités à implémenter** :
| ID | Vulnérabilité | Endpoint exemple |
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
| V10 | Insufficient Logging | Absence de traces |

### Phase 2 : GraphQL + Challenges Étendus

**Objectif** : Ajouter une couche GraphQL avec vulnérabilités spécifiques

**Livrables** :
- Endpoint `/graphql` avec schema complet
- Vulnérabilités spécifiques GraphQL
- Challenges supplémentaires

**Vulnérabilités GraphQL spécifiques** :
| ID | Vulnérabilité | Description |
|----|---------------|-------------|
| G01 | Introspection exposée | Schema accessible en production |
| G02 | Nested queries (DoS) | Requêtes imbriquées sans limite |
| G03 | Batching attacks | Multiples opérations en une requête |
| G04 | Field suggestions | Aide à l'énumération |
| G05 | Authorization bypass | Vérifications manquantes sur resolvers |

### Phase 3 : Mode Documentation

**Objectif** : Ajouter des explications pédagogiques

**Livrables** :
- Toggle challenge/documentation dans l'API
- Explications détaillées pour chaque vulnérabilité
- Exemples de code vulnérable vs sécurisé
- Références OWASP et CWE

**Structure documentation par vulnérabilité** :
```
{
  "id": "V01",
  "name": "Broken Object Level Authorization",
  "description": "...",
  "vulnerable_code": "...",
  "secure_code": "...",
  "exploitation": "...",
  "remediation": "...",
  "references": ["OWASP API1:2023", "CWE-639"]
}
```

### Phase 4 : Frontend d'Introduction

**Objectif** : Interface web pour guider les débutants

**Livrables** :
- Dashboard avec progression
- Interface pour tester les endpoints
- Visualisation des requêtes/réponses
- Tutoriels interactifs

---

## Stack Technique

### Implémentation Principale : Python

```
python-fastapi/
├── app/
│   ├── __init__.py
│   ├── main.py              # Point d'entrée FastAPI
│   ├── config.py            # Configuration
│   ├── database.py          # Connexion DB
│   │
│   ├── models/              # Modèles SQLAlchemy
│   │   ├── user.py
│   │   ├── product.py
│   │   └── order.py
│   │
│   ├── schemas/             # Schemas Pydantic
│   │   └── ...
│   │
│   ├── routers/             # Endpoints REST
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── products.py
│   │   └── tools.py
│   │
│   ├── graphql/             # Schema GraphQL (Phase 2)
│   │   ├── schema.py
│   │   ├── queries.py
│   │   └── mutations.py
│   │
│   ├── challenges/          # Système de flags
│   │   ├── flags.py
│   │   └── validator.py
│   │
│   ├── docs/                # Mode documentation (Phase 3)
│   │   └── vulnerabilities.json
│   │
│   └── vulnerabilities/     # Code vulnérable isolé
│       ├── bola.py
│       ├── sqli.py
│       └── ...
│
├── tests/
│   ├── exploits/            # Scripts d'exploitation
│   └── unit/
│
├── docker-compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

### Dépendances Python (Phase 1)

```
fastapi>=0.109.0
uvicorn>=0.27.0
sqlalchemy>=2.0.0
pydantic>=2.0.0
python-jose>=3.3.0          # JWT
passlib>=1.7.0              # Hashing (volontairement mal utilisé)
python-multipart>=0.0.6
```

### Dépendances supplémentaires (Phase 2)

```
strawberry-graphql>=0.217.0  # GraphQL
```

---

## Contrat API Commun

Pour faciliter les réimplémentations dans d'autres langages, un contrat OpenAPI sera maintenu :

```
specs/
├── openapi.yaml             # Spécification REST
├── graphql.schema           # Schema GraphQL
├── challenges.json          # Définition des challenges/flags
├── test-suite/              # Tests d'exploitation portables
│   ├── test_bola.py
│   ├── test_sqli.py
│   └── ...
└── data/
    └── seed.sql             # Données initiales communes
```

---

## Réimplémentations Futures

Le projet est conçu pour être réimplémenté dans d'autres langages :

| Priorité | Langage | Framework | Justification |
|----------|---------|-----------|---------------|
| 1 | Python | FastAPI | Implémentation de référence |
| 2 | JavaScript | Express.js | Très répandu, écosystème large |
| 3 | Java | Spring Boot | Contexte entreprise |
| 4 | Go | Gin | Cloud-native, moderne |
| 5 | PHP | Laravel | Legacy, encore très présent |

### Règles pour les réimplémentations

1. **Respecter le contrat OpenAPI** — Mêmes endpoints, mêmes réponses
2. **Mêmes vulnérabilités** — Comportement identique exploitable
3. **Mêmes flags** — Permettre les mêmes challenges
4. **Tests partagés** — Passer la même suite de tests d'exploitation
5. **Structure similaire** — Faciliter la comparaison entre implémentations

---

## Environnement de Développement

### Prérequis

- Python 3.11+
- Docker & Docker Compose
- SQLite (dev) / PostgreSQL (prod)

### Lancement rapide

```bash
# Cloner le projet
git clone <repo>
cd vulnapi

# Environnement virtuel
python -m venv venv
source venv/bin/activate

# Dépendances
pip install -r requirements.txt

# Lancer l'API
uvicorn app.main:app --reload

# Ou via Docker
docker-compose up
```

### Variables d'environnement

```
VULNAPI_MODE=challenge|documentation
VULNAPI_DB_URL=sqlite:///./vulnapi.db
VULNAPI_SECRET_KEY=intentionally-weak-secret
VULNAPI_DEBUG=true
```

---

## Contexte pour Claude

### Lors des prochaines sessions, rappeler :

1. **Projet** : VulnAPI - API volontairement vulnérable pour l'apprentissage
2. **Phase actuelle** : Phase 1 terminée (REST + Challenges)
3. **Stack** : Python/FastAPI, puis multi-langages
4. **Approche** : Incrémentale, chaque phase livre de la valeur
5. **Fichier de référence** : Ce document `PROJECT_SPEC.md`

### Commandes utiles pour Claude

- "Continue le développement de VulnAPI phase X"
- "Ajoute la vulnérabilité Y à l'API REST"
- "Prépare la réimplémentation en [langage]"
- "Génère les tests d'exploitation pour la vulnérabilité Z"

---

## Licence et Avertissement

**AVERTISSEMENT** : Ce logiciel est conçu à des fins éducatives uniquement. Les vulnérabilités sont intentionnelles. Ne jamais déployer en production ni utiliser contre des systèmes sans autorisation.

**Licence** : [À définir - MIT / GPL / etc.]

---

## Historique des décisions

| Date | Décision |
|------|----------|
| 2026-01-11 | Création du projet, choix de l'approche en 4 phases |
| 2026-01-11 | Python/FastAPI comme implémentation de référence |
| 2026-01-11 | Architecture multi-langages prévue dès le départ |
| 2026-01-11 | Phase 1 terminée : API REST + 10 vulnérabilités OWASP + système de flags |
