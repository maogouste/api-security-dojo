//! Order endpoints
//!
//! Vulnerabilities:
//! - V01: BOLA - Access any user's orders

use actix_web::{web, HttpResponse, HttpRequest};
use crate::db::{DbPool, Order, OrderItem, ErrorResponse};
use crate::api::auth::extract_user_from_token;

/// V01: BOLA - List orders (no user filtering)
pub async fn list_orders(
    pool: web::Data<DbPool>,
) -> HttpResponse {
    // V01: Returns ALL orders, not just current user's
    let orders: Vec<Order> = sqlx::query_as("SELECT * FROM orders")
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(orders)
}

/// V01: BOLA - Get any order by ID
pub async fn get_order(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let order_id = path.into_inner();

    // V01: No check if order belongs to current user
    let order: Option<Order> = sqlx::query_as("SELECT * FROM orders WHERE id = ?")
        .bind(order_id)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

    match order {
        None => HttpResponse::NotFound().json(ErrorResponse {
            error: "Order not found".to_string(),
            detail: None,
        }),
        Some(order) => {
            // Get order items
            let items: Vec<OrderItem> = sqlx::query_as(
                "SELECT * FROM order_items WHERE order_id = ?"
            )
            .bind(order_id)
            .fetch_all(pool.get_ref())
            .await
            .unwrap_or_default();

            HttpResponse::Ok().json(serde_json::json!({
                "order": order,
                "items": items
            }))
        }
    }
}

/// V01: BOLA - Get orders by user ID (can query any user)
pub async fn get_user_orders(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // V01: No check if requester is authorized to view this user's orders
    let orders: Vec<Order> = sqlx::query_as(
        "SELECT * FROM orders WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    HttpResponse::Ok().json(orders)
}

/// Create order
pub async fn create_order(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    // Get user from token (if provided)
    let user_id = extract_user_from_token(&req)
        .map(|c| c.sub)
        .unwrap_or(1); // Default to user 1 if no auth

    let shipping_address = body.get("shipping_address")
        .and_then(|v| v.as_str())
        .unwrap_or("No address");

    let result = sqlx::query(
        "INSERT INTO orders (user_id, status, total, shipping_address) VALUES (?, 'pending', 0, ?)"
    )
    .bind(user_id)
    .bind(shipping_address)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            let order_id = res.last_insert_rowid();
            HttpResponse::Created().json(serde_json::json!({
                "id": order_id,
                "user_id": user_id,
                "status": "pending",
                "message": "Order created"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to create order".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}
