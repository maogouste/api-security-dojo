//! GraphQL HTTP handlers

use actix_web::{web, HttpResponse};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use crate::graphql::DojoSchema;

/// GraphQL endpoint handler
/// G01: Accepts introspection queries
/// G02: No depth limiting
/// G03: Accepts batched queries
pub async fn graphql_handler(
    schema: web::Data<DojoSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// GraphQL Playground - G01: Exposed in production
pub async fn graphql_playground() -> HttpResponse {
    let source = playground_source(GraphQLPlaygroundConfig::new("/graphql"));
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(source)
}

/// GraphQL introspection helper endpoint
/// G01: Explicitly documents that introspection is enabled
pub async fn graphql_introspection_hint() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "hint": "GraphQL introspection is enabled",
        "try": "Send a POST request to /graphql with: { \"query\": \"{ __schema { types { name } } }\" }",
        "playground": "/graphql/playground",
        "vulnerabilities": [
            "G01: Introspection enabled - discover entire schema",
            "G02: No depth limiting - nested queries can cause DoS",
            "G03: No complexity limiting - batch queries allowed",
            "G04: Field suggestions reveal schema structure",
            "G05: No authorization on sensitive fields"
        ]
    }))
}
