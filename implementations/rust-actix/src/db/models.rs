use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub ssn: Option<String>,
    pub credit_card: Option<String>,
    pub secret_note: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub api_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub role: String,
    pub is_active: bool,
}

/// V03: Excessive Data Exposure - returns all fields including sensitive ones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserExposed {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub ssn: Option<String>,
    pub credit_card: Option<String>,
    pub secret_note: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub api_key: Option<String>,
}

impl From<User> for UserPublic {
    fn from(user: User) -> Self {
        UserPublic {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_active: user.is_active,
        }
    }
}

impl From<User> for UserExposed {
    fn from(user: User) -> Self {
        UserExposed {
            id: user.id,
            username: user.username,
            email: user.email,
            password_hash: user.password_hash,
            ssn: user.ssn,
            credit_card: user.credit_card,
            secret_note: user.secret_note,
            role: user.role,
            is_active: user.is_active,
            api_key: user.api_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Product {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub price: f64,
    pub stock: i64,
    pub category: Option<String>,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Order {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub total: f64,
    pub shipping_address: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrderItem {
    pub id: i64,
    pub order_id: i64,
    pub product_id: i64,
    pub quantity: i64,
    pub price: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Flag {
    pub id: i64,
    pub vulnerability_id: String,
    pub flag_value: String,
    pub hint: Option<String>,
    pub points: i64,
}

// Request/Response DTOs

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub user: UserPublic,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub is_admin: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PingRequest {
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct PingResponse {
    pub output: String,
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ApiInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub detail: Option<String>,
}
