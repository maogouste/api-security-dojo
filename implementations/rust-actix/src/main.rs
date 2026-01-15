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
use log::{info, error};

use crate::db::{init_db, HealthResponse, ApiInfo};
use crate::graphql::{create_schema, graphql_handler, graphql_playground, graphql_introspection_hint};

/// Check if running in a production-like environment and block startup.
/// This application is INTENTIONALLY VULNERABLE and should NEVER
/// be deployed in production environments.
fn check_production_environment() {
    let indicators: Vec<(&str, Option<String>)> = vec![
        ("PRODUCTION", std::env::var("PRODUCTION").ok()),
        ("PROD", std::env::var("PROD").ok()),
        ("NODE_ENV=production", std::env::var("NODE_ENV").ok().filter(|v| v == "production").map(|_| "true".to_string())),
        ("ENVIRONMENT=production", std::env::var("ENVIRONMENT").ok().filter(|v| v == "production").map(|_| "true".to_string())),
        ("AWS_EXECUTION_ENV", std::env::var("AWS_EXECUTION_ENV").ok()),
        ("AWS_LAMBDA_FUNCTION_NAME", std::env::var("AWS_LAMBDA_FUNCTION_NAME").ok()),
        ("KUBERNETES_SERVICE_HOST", std::env::var("KUBERNETES_SERVICE_HOST").ok()),
        ("ECS_CONTAINER_METADATA_URI", std::env::var("ECS_CONTAINER_METADATA_URI").ok()),
        ("GOOGLE_CLOUD_PROJECT", std::env::var("GOOGLE_CLOUD_PROJECT").ok()),
        ("HEROKU_APP_NAME", std::env::var("HEROKU_APP_NAME").ok()),
        ("VERCEL", std::env::var("VERCEL").ok()),
        ("RENDER", std::env::var("RENDER").ok()),
    ];

    let detected: Vec<_> = indicators.into_iter()
        .filter_map(|(k, v)| v.map(|val| (k, val)))
        .collect();

    if !detected.is_empty() {
        eprintln!("\n================================================================================");
        eprintln!("                    CRITICAL SECURITY WARNING");
        eprintln!("================================================================================\n");
        eprintln!("  API Security Dojo has detected a PRODUCTION-LIKE environment!\n");
        eprintln!("  Detected indicators:");
        for (k, v) in &detected {
            eprintln!("    - {}: {}", k, v);
        }
        eprintln!("\n  THIS APPLICATION IS INTENTIONALLY VULNERABLE!");
        eprintln!("  It contains security vulnerabilities by design for educational purposes.\n");
        eprintln!("  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!\n");
        eprintln!("================================================================================\n");

        if std::env::var("DOJO_FORCE_START").ok().as_deref() != Some("true") {
            eprintln!("  To override this safety check (NOT RECOMMENDED), set:");
            eprintln!("    DOJO_FORCE_START=true\n");
            std::process::exit(1);
        } else {
            error!("WARNING: DOJO_FORCE_START=true detected.");
            error!("Proceeding despite production environment detection.");
            error!("YOU HAVE BEEN WARNED!");
        }
    }
}

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

    // Check production environment before proceeding
    check_production_environment();

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
            .route("/api/v1/users", web::get().to(api::v1_list_users))
            .route("/api/v1/users/{id}", web::get().to(api::v1_get_user))
            .route("/api/v1/users/search", web::get().to(api::v1_search_users))
            .route("/api/v1/admin/users", web::get().to(api::v1_admin_users))
            .route("/api/v1/reset-password", web::post().to(api::v1_reset_password))
            // GraphQL (G01-G05)
            .route("/graphql", web::post().to(graphql_handler))
            .route("/graphql/", web::post().to(graphql_handler))
            .route("/graphql", web::get().to(graphql_introspection_hint))
            .route("/graphql/", web::get().to(graphql_introspection_hint))
            .route("/graphql/playground", web::get().to(graphql_playground))
    })
    .bind((host, port))?
    .run()
    .await
}
