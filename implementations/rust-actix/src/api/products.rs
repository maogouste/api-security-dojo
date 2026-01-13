//! Product endpoints
//!
//! Vulnerabilities:
//! - V06: SQL Injection in search

use actix_web::{web, HttpResponse};
use crate::db::{DbPool, Product, SearchQuery, ErrorResponse};

/// List all products
pub async fn list_products(
    pool: web::Data<DbPool>,
) -> HttpResponse {
    let products: Vec<Product> = sqlx::query_as("SELECT * FROM products WHERE is_active = 1")
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(products)
}

/// Get product by ID
pub async fn get_product(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let product_id = path.into_inner();

    let product: Option<Product> = sqlx::query_as("SELECT * FROM products WHERE id = ?")
        .bind(product_id)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

    match product {
        None => HttpResponse::NotFound().json(ErrorResponse {
            error: "Product not found".to_string(),
            detail: None,
        }),
        Some(product) => HttpResponse::Ok().json(product),
    }
}

/// V06: SQL Injection - Search products
/// The search query is directly interpolated into SQL
pub async fn search_products(
    pool: web::Data<DbPool>,
    query: web::Query<SearchQuery>,
) -> HttpResponse {
    // V06: SQL Injection - user input directly in query
    let search_term = query.q.clone().unwrap_or_default();
    let category = query.category.clone();

    // VULNERABLE: Direct string interpolation
    let sql = if let Some(cat) = category {
        format!(
            "SELECT * FROM products WHERE (name LIKE '%{}%' OR description LIKE '%{}%') AND category = '{}'",
            search_term, search_term, cat
        )
    } else {
        format!(
            "SELECT * FROM products WHERE name LIKE '%{}%' OR description LIKE '%{}%'",
            search_term, search_term
        )
    };

    // Execute vulnerable query
    match sqlx::query_as::<_, Product>(&sql)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(products) => HttpResponse::Ok().json(products),
        Err(e) => {
            // V06: Error message reveals SQL details
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Database error".to_string(),
                detail: Some(format!("SQL Error: {}", e)),
            })
        }
    }
}

/// V06: SQL Injection - Get product by name
/// Alternative vulnerable endpoint
pub async fn get_product_by_name(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> HttpResponse {
    let name = path.into_inner();

    // VULNERABLE: Direct interpolation
    let sql = format!("SELECT * FROM products WHERE name = '{}'", name);

    match sqlx::query_as::<_, Product>(&sql)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(products) => {
            if products.is_empty() {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: "Product not found".to_string(),
                    detail: None,
                })
            } else {
                HttpResponse::Ok().json(&products[0])
            }
        }
        Err(e) => {
            // Leak SQL error
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Query failed".to_string(),
                detail: Some(e.to_string()),
            })
        }
    }
}
