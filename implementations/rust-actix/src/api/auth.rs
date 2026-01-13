//! Authentication endpoints
//!
//! Vulnerabilities:
//! - V02: User enumeration via different error messages
//! - V04: No rate limiting on login

use actix_web::{web, HttpResponse, HttpRequest};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use crate::db::{DbPool, User, LoginRequest, LoginResponse, UserPublic, ErrorResponse};

// Weak secret key - V08: Security Misconfiguration
const JWT_SECRET: &str = "super_secret_key_123";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

/// V02: Broken Authentication - User enumeration
/// Different error messages reveal if username exists
/// V04: No rate limiting
pub async fn login(
    pool: web::Data<DbPool>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    // V02: Different error for non-existent user vs wrong password
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

    match user {
        None => {
            // V02: Reveals that username doesn't exist
            HttpResponse::Unauthorized().json(ErrorResponse {
                error: "User not found".to_string(),
                detail: Some(format!("No user with username '{}'", body.username)),
            })
        }
        Some(user) => {
            // Simple password check (in real app, use bcrypt::verify)
            // For demo, we accept "password123" for john/jane, "admin123" for admin
            let valid = match user.username.as_str() {
                "admin" => body.password == "admin123",
                "john" | "jane" => body.password == "password123" || body.password == "password456",
                _ => false,
            };

            if !valid {
                // V02: Different error reveals password is wrong (user exists)
                return HttpResponse::Unauthorized().json(ErrorResponse {
                    error: "Invalid password".to_string(),
                    detail: Some("The password is incorrect".to_string()),
                });
            }

            // Generate JWT
            let expiration = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .expect("valid timestamp")
                .timestamp() as usize;

            let claims = Claims {
                sub: user.id,
                username: user.username.clone(),
                role: user.role.clone(),
                exp: expiration,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
            )
            .unwrap();

            HttpResponse::Ok().json(LoginResponse {
                access_token: token,
                token_type: "bearer".to_string(),
                user: UserPublic::from(user),
            })
        }
    }
}

/// Extract user from JWT token
pub fn extract_user_from_token(req: &HttpRequest) -> Option<Claims> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    if !auth_str.starts_with("Bearer ") {
        return None;
    }

    let token = &auth_str[7..];

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .ok()?;

    Some(token_data.claims)
}

/// Get current user info
pub async fn me(
    req: HttpRequest,
    pool: web::Data<DbPool>,
) -> HttpResponse {
    match extract_user_from_token(&req) {
        None => HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Not authenticated".to_string(),
            detail: None,
        }),
        Some(claims) => {
            let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
                .bind(claims.sub)
                .fetch_optional(pool.get_ref())
                .await
                .unwrap_or(None);

            match user {
                None => HttpResponse::NotFound().json(ErrorResponse {
                    error: "User not found".to_string(),
                    detail: None,
                }),
                Some(user) => HttpResponse::Ok().json(UserPublic::from(user)),
            }
        }
    }
}
