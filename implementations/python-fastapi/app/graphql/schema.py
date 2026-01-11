"""GraphQL Schema assembly.

This file creates the main GraphQL schema with all vulnerabilities enabled.

VULNERABILITIES:
- G01: Introspection enabled (schema accessible)
- G02: No query depth limits
- G03: No query complexity limits
- G04: Field suggestions enabled in errors
"""

import strawberry
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, HTMLResponse
from strawberry.fastapi import GraphQLRouter

from app.graphql.queries import Query
from app.graphql.mutations import Mutation
from app.graphql.context import get_context


# Create the schema
# VULNERABILITY G01: Introspection is enabled by default
# VULNERABILITY G02: No max_depth limit
# VULNERABILITY G03: No complexity limit
# VULNERABILITY G04: Field suggestions enabled in errors
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
)


async def execute_query(request: Request, body: dict) -> dict[str, Any]:
    """Execute a single GraphQL query and return response data."""
    query = body.get("query", "")
    variables = body.get("variables")
    operation_name = body.get("operationName")

    context = await get_context(request)
    result = await schema.execute(
        query,
        variable_values=variables,
        operation_name=operation_name,
        context_value=context,
    )

    response_data: dict[str, Any] = {"data": result.data}
    if result.errors:
        response_data["errors"] = [
            {"message": str(e), "locations": e.locations, "path": e.path}
            for e in result.errors
        ]
    return response_data


def create_graphql_router() -> APIRouter:
    """
    Create the GraphQL router for FastAPI with batching support.

    VULNERABILITIES:
    - G01: Introspection enabled (graphiql=True exposes schema)
    - G02: No query depth validation
    - G03: Batching enabled - no limits on batch size
    - G04: Detailed error messages with field suggestions
    """
    router = APIRouter()

    # Standard Strawberry router for GraphiQL UI
    strawberry_router = GraphQLRouter(
        schema,
        context_getter=get_context,
        graphiql=True,  # VULNERABILITY: GraphiQL UI exposed in production
    )

    @router.get("/")
    async def graphql_get(request: Request):
        """Serve GraphiQL UI."""
        return await strawberry_router.handle_graphiql(request)

    @router.post("/")
    async def graphql_post(request: Request):
        """
        Handle GraphQL POST requests.

        VULNERABILITY G03: Batching enabled without limits.
        Attackers can send arrays of operations to bypass rate limiting
        or amplify attacks.
        """
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"errors": [{"message": "Invalid JSON"}]}, status_code=400)

        # VULNERABILITY G03: Process batched queries without limits
        if isinstance(body, list):
            # Batched query - process each one without any limits
            results = []
            for operation in body:
                response_data = await execute_query(request, operation)
                results.append(response_data)
            return JSONResponse(results)
        else:
            # Single query
            response_data = await execute_query(request, body)
            return JSONResponse(response_data)

    return router
