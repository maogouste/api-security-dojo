"""GraphQL schema and resolvers (Phase 2).

This module implements a vulnerable GraphQL API with the following
intentional security issues:

- G01: Introspection Exposed - Schema is accessible in production
- G02: Nested Queries (DoS) - No depth/complexity limits
- G03: Batching Attacks - Multiple operations allowed per request
- G04: Field Suggestions - Error messages help enumerate fields
- G05: Authorization Bypass - Missing auth checks on resolvers
"""

from app.graphql.schema import schema, create_graphql_router

__all__ = ["schema", "create_graphql_router"]
