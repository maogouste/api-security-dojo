//! API Security Dojo - Rust/Actix-web implementation
//!
//! An intentionally vulnerable API for learning API security.
//! DO NOT deploy in production!
//!
//! Vulnerabilities implemented:
//! - V01: Broken Object Level Authorization (BOLA)
//! - V02: Broken Authentication
//! - V03: Excessive Data Exposure
//! - V04: Lack of Rate Limiting
//! - V05: Mass Assignment
//! - V06: SQL Injection
//! - V07: Command Injection
//! - V08: Security Misconfiguration
//! - V09: Improper Assets Management
//! - V10: Insufficient Logging
//! - G01: GraphQL Introspection
//! - G02: GraphQL Nested Queries (DoS)
//! - G03: GraphQL Batching
//! - G04: GraphQL Field Suggestions
//! - G05: GraphQL Authorization Bypass

mod db;
mod api;
mod graphql;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer, HttpResponse, middleware::Logger};
use log::info;

use crate::db::{init_db, HealthResponse, ApiInfo};
use crate::graphql::{create_schema, graphql_handler, graphql_playground, graphql_introspection_hint};

/// Health check endpoint
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
    })
}

/// API info endpoint
async fn index() -> HttpResponse {
    HttpResponse::Ok().json(ApiInfo {
        name: "API Security Dojo".to_string(),
        version: "0.1.0".to_string(),
        description: "Intentionally vulnerable API for learning - Rust/Actix-web".to_string(),
        endpoints: vec![
            "/health".to_string(),
            "/api/login".to_string(),
            "/api/users".to_string(),
            "/api/products".to_string(),
            "/api/orders".to_string(),
            "/api/tools/ping".to_string(),
            "/api/v1/*".to_string(),
            "/graphql".to_string(),
        ],
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load .env file if present
    dotenv::dotenv().ok();

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3006".to_string())
        .parse()
        .unwrap_or(3006);

    info!("===========================================");
    info!("  API Security Dojo - Rust/Actix-web");
    info!("  WARNING: Intentionally vulnerable!");
    info!("===========================================");
    info!("Starting server on {}:{}", host, port);

    // Initialize database
    let pool = init_db().await.expect("Failed to initialize database");

    // Create GraphQL schema
    let schema = create_schema(pool.clone());

    HttpServer::new(move || {
        // V08: CORS misconfiguration - allows all origins
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .wrap(Logger::default()) // V10: Basic logging only
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(schema.clone()))
            // Root endpoints
            .route("/", web::get().to(index))
            .route("/health", web::get().to(health))
            // Auth endpoints
            .route("/api/login", web::post().to(api::login))
            .route("/api/me", web::get().to(api::me))
            // User endpoints (V01, V03, V05)
            .route("/api/users", web::get().to(api::list_users))
            .route("/api/users", web::post().to(api::create_user))
            .route("/api/users/{id}", web::get().to(api::get_user))
            .route("/api/users/{id}", web::put().to(api::update_user))
            .route("/api/users/{id}", web::delete().to(api::delete_user))
            // Product endpoints (V06)
            .route("/api/products", web::get().to(api::list_products))
            .route("/api/products/search", web::get().to(api::search_products))
            .route("/api/products/{id}", web::get().to(api::get_product))
            .route("/api/products/name/{name}", web::get().to(api::get_product_by_name))
            // Order endpoints (V01)
            .route("/api/orders", web::get().to(api::list_orders))
            .route("/api/orders", web::post().to(api::create_order))
            .route("/api/orders/{id}", web::get().to(api::get_order))
            .route("/api/users/{id}/orders", web::get().to(api::get_user_orders))
            // Tool endpoints (V07)
            .route("/api/tools/ping", web::post().to(api::ping))
            .route("/api/tools/dns", web::get().to(api::dns_lookup))
            .route("/api/debug", web::get().to(api::debug_info))
            // Legacy API v1 (V09)
            .route("/api/v1/users/{id}", web::get().to(api::v1_get_user))
            .route("/api/v1/users/search", web::get().to(api::v1_search_users))
            .route("/api/v1/admin/users", web::get().to(api::v1_admin_users))
            .route("/api/v1/reset-password", web::post().to(api::v1_reset_password))
            // GraphQL (G01-G05)
            .route("/graphql", web::post().to(graphql_handler))
            .route("/graphql", web::get().to(graphql_introspection_hint))
            .route("/graphql/playground", web::get().to(graphql_playground))
    })
    .bind((host, port))?
    .run()
    .await
}
