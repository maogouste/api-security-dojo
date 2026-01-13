//! User management endpoints
//!
//! Vulnerabilities:
//! - V01: BOLA - Access any user's data without authorization
//! - V03: Excessive Data Exposure - Sensitive fields returned
//! - V05: Mass Assignment - Can set role/is_admin via request

use actix_web::{web, HttpResponse};
use crate::db::{DbPool, User, UserExposed, CreateUserRequest, UpdateUserRequest, ErrorResponse};

/// V01: BOLA - No authorization check, any user can access any user's data
/// V03: Excessive Data Exposure - Returns sensitive fields
pub async fn get_user(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // V01: No check if requester is authorized to view this user
    // V03: Returns all fields including sensitive ones
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
        // V03: Excessive Data Exposure - returning all fields
        Some(user) => HttpResponse::Ok().json(UserExposed::from(user)),
    }
}

/// List all users
/// V03: Excessive Data Exposure
pub async fn list_users(
    pool: web::Data<DbPool>,
) -> HttpResponse {
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users")
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    // V03: Exposing all user data including sensitive fields
    let exposed: Vec<UserExposed> = users.into_iter().map(UserExposed::from).collect();
    HttpResponse::Ok().json(exposed)
}

/// Create new user
/// V05: Mass Assignment - role/is_admin can be set by client
pub async fn create_user(
    pool: web::Data<DbPool>,
    body: web::Json<CreateUserRequest>,
) -> HttpResponse {
    // V05: Mass Assignment - accepting role from user input
    let role = if body.is_admin.unwrap_or(false) {
        "admin".to_string()
    } else {
        body.role.clone().unwrap_or_else(|| "user".to_string())
    };

    // Simple password hash (in production, use bcrypt)
    let password_hash = format!("$2b$12${}", body.password);

    let result = sqlx::query(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)"
    )
    .bind(&body.username)
    .bind(&body.email)
    .bind(&password_hash)
    .bind(&role)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            let user_id = res.last_insert_rowid();
            HttpResponse::Created().json(serde_json::json!({
                "id": user_id,
                "username": body.username,
                "email": body.email,
                "role": role,
                "message": "User created successfully"
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "Failed to create user".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}

/// Update user
/// V01: BOLA - Can update any user
/// V05: Mass Assignment - Can escalate privileges
pub async fn update_user(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    body: web::Json<UpdateUserRequest>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // V01: No authorization check - can update any user

    // Build update query dynamically
    let mut updates = Vec::new();
    let mut values: Vec<String> = Vec::new();

    if let Some(ref username) = body.username {
        updates.push("username = ?");
        values.push(username.clone());
    }
    if let Some(ref email) = body.email {
        updates.push("email = ?");
        values.push(email.clone());
    }
    // V05: Mass Assignment - allowing role change
    if let Some(ref role) = body.role {
        updates.push("role = ?");
        values.push(role.clone());
    }
    // V05: Mass Assignment - is_admin -> role = 'admin'
    if body.is_admin == Some(true) {
        updates.push("role = ?");
        values.push("admin".to_string());
    }

    if updates.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "No fields to update".to_string(),
            detail: None,
        });
    }

    let query = format!(
        "UPDATE users SET {} WHERE id = {}",
        updates.join(", "),
        user_id
    );

    // Execute with dynamic values
    let mut q = sqlx::query(&query);
    for value in &values {
        q = q.bind(value);
    }

    match q.execute(pool.get_ref()).await {
        Ok(_) => {
            // Return updated user
            let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(pool.get_ref())
                .await
                .unwrap_or(None);

            match user {
                Some(user) => HttpResponse::Ok().json(UserExposed::from(user)),
                None => HttpResponse::NotFound().json(ErrorResponse {
                    error: "User not found".to_string(),
                    detail: None,
                }),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "Failed to update user".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}

/// Delete user
/// V01: BOLA - Can delete any user
pub async fn delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // V01: No authorization check

    match sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(pool.get_ref())
        .await
    {
        Ok(res) => {
            if res.rows_affected() > 0 {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "User deleted successfully"
                }))
            } else {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: "User not found".to_string(),
                    detail: None,
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to delete user".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}
