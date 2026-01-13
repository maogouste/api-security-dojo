//! Legacy API endpoints
//!
//! V09: Improper Assets Management - Old API versions still accessible

use actix_web::{web, HttpResponse};
use crate::db::{DbPool, User, UserExposed, ErrorResponse};

/// V09: Legacy v1 API - less secure, deprecated but still works
pub async fn v1_get_user(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // V09: Old API has no auth and exposes everything
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

    match user {
        None => HttpResponse::NotFound().json(ErrorResponse {
            error: "User not found".to_string(),
            detail: None,
        }),
        Some(user) => {
            // V09: Legacy API exposes even more data
            HttpResponse::Ok().json(serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "password_hash": user.password_hash,
                "ssn": user.ssn,
                "credit_card": user.credit_card,
                "secret_note": user.secret_note,
                "role": user.role,
                "api_key": user.api_key,
                "internal_notes": "This user was migrated from legacy system",
                "legacy_api": true,
                "deprecation_warning": "This API version is deprecated"
            }))
        }
    }
}

/// V09: Legacy user list with SQL injection
pub async fn v1_search_users(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let search = query.get("q").cloned().unwrap_or_default();

    // V09 + V06: Legacy API with SQL injection
    let sql = format!(
        "SELECT * FROM users WHERE username LIKE '%{}%' OR email LIKE '%{}%'",
        search, search
    );

    match sqlx::query_as::<_, User>(&sql)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(users) => {
            let exposed: Vec<UserExposed> = users.into_iter().map(UserExposed::from).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "users": exposed,
                "api_version": "v1",
                "deprecated": true
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Legacy API error".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}

/// V09: Legacy admin endpoint - no auth required
pub async fn v1_admin_users(
    pool: web::Data<DbPool>,
) -> HttpResponse {
    // V09: Admin endpoint with no authentication
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users")
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let exposed: Vec<UserExposed> = users.into_iter().map(UserExposed::from).collect();

    HttpResponse::Ok().json(serde_json::json!({
        "admin_data": true,
        "users": exposed,
        "api_version": "v1",
        "warning": "This endpoint should require admin authentication"
    }))
}

/// V09: Legacy password reset - insecure
pub async fn v1_reset_password(
    pool: web::Data<DbPool>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let username = body.get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if username.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Username required".to_string(),
            detail: None,
        });
    }

    // V09: Legacy reset just returns the password hash (very insecure!)
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

    match user {
        None => HttpResponse::NotFound().json(ErrorResponse {
            error: "User not found".to_string(),
            detail: None,
        }),
        Some(user) => {
            // V09: Leaking password hash in response
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Password reset initiated",
                "username": user.username,
                "password_hash": user.password_hash,
                "reset_token": format!("legacy_reset_{}", user.id),
                "api_version": "v1",
                "security_warning": "This response contains sensitive data"
            }))
        }
    }
}
