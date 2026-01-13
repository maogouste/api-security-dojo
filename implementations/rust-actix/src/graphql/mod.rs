//! GraphQL implementation
//!
//! Vulnerabilities:
//! - G01: Introspection enabled in production
//! - G02: No query depth limiting (DoS via nested queries)
//! - G03: No query complexity limiting (batching attacks)
//! - G04: Field suggestions reveal schema
//! - G05: Authorization bypass

use async_graphql::{Context, Object, SimpleObject, InputObject, Schema, EmptySubscription};
use crate::db::DbPool;

pub mod schema;
pub use schema::*;

// GraphQL Types

#[derive(SimpleObject, Clone)]
pub struct GqlUser {
    pub id: i64,
    pub username: String,
    pub email: String,
    /// G05: Sensitive field exposed without auth check
    pub ssn: Option<String>,
    /// G05: Sensitive field exposed
    pub credit_card: Option<String>,
    pub role: String,
    /// G02: Nested relationship enables deep queries
    pub orders: Vec<GqlOrder>,
}

#[derive(SimpleObject, Clone)]
pub struct GqlOrder {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub total: f64,
    /// G02: Nested relationship for DoS
    pub user: Option<Box<GqlUser>>,
    pub items: Vec<GqlOrderItem>,
}

#[derive(SimpleObject, Clone)]
pub struct GqlOrderItem {
    pub id: i64,
    pub product_id: i64,
    pub quantity: i64,
    pub price: f64,
    /// G02: Another nested relationship
    pub product: Option<GqlProduct>,
}

#[derive(SimpleObject, Clone)]
pub struct GqlProduct {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub price: f64,
    pub stock: i64,
    pub category: Option<String>,
}

#[derive(SimpleObject)]
pub struct GqlFlag {
    pub id: i64,
    pub vulnerability_id: String,
    pub flag_value: String,
    pub hint: Option<String>,
}

// Input types for mutations

#[derive(InputObject)]
pub struct CreateUserInput {
    pub username: String,
    pub email: String,
    pub password: String,
    /// G05: Can set admin role
    pub role: Option<String>,
}

#[derive(InputObject)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(SimpleObject)]
pub struct AuthPayload {
    pub token: String,
    pub user: GqlUser,
}

// Query root

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// G05: No auth required to query users
    async fn users(&self, ctx: &Context<'_>) -> Vec<GqlUser> {
        let pool = ctx.data::<DbPool>().unwrap();

        let users: Vec<crate::db::User> = sqlx::query_as("SELECT * FROM users")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

        users.into_iter().map(|u| user_to_gql(u, pool.clone())).collect()
    }

    /// G05: BOLA - can query any user by ID
    async fn user(&self, ctx: &Context<'_>, id: i64) -> Option<GqlUser> {
        let pool = ctx.data::<DbPool>().unwrap();

        let user: Option<crate::db::User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await
            .ok()?;

        user.map(|u| user_to_gql(u, pool.clone()))
    }

    /// G03: Batching - can query multiple users at once
    async fn users_by_ids(&self, ctx: &Context<'_>, ids: Vec<i64>) -> Vec<GqlUser> {
        let pool = ctx.data::<DbPool>().unwrap();

        let mut users = Vec::new();
        for id in ids {
            if let Ok(Some(user)) = sqlx::query_as::<_, crate::db::User>(
                "SELECT * FROM users WHERE id = ?"
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            {
                users.push(user_to_gql(user, pool.clone()));
            }
        }
        users
    }

    async fn products(&self, ctx: &Context<'_>) -> Vec<GqlProduct> {
        let pool = ctx.data::<DbPool>().unwrap();

        let products: Vec<crate::db::Product> = sqlx::query_as(
            "SELECT * FROM products WHERE is_active = 1"
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        products.into_iter().map(product_to_gql).collect()
    }

    async fn product(&self, ctx: &Context<'_>, id: i64) -> Option<GqlProduct> {
        let pool = ctx.data::<DbPool>().unwrap();

        let product: Option<crate::db::Product> = sqlx::query_as(
            "SELECT * FROM products WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()?;

        product.map(product_to_gql)
    }

    /// G05: Can query any order without auth
    async fn orders(&self, ctx: &Context<'_>) -> Vec<GqlOrder> {
        let pool = ctx.data::<DbPool>().unwrap();

        let orders: Vec<crate::db::Order> = sqlx::query_as("SELECT * FROM orders")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

        let mut result = Vec::new();
        for order in orders {
            result.push(order_to_gql(order, pool.clone()).await);
        }
        result
    }

    async fn order(&self, ctx: &Context<'_>, id: i64) -> Option<GqlOrder> {
        let pool = ctx.data::<DbPool>().unwrap();

        let order: Option<crate::db::Order> = sqlx::query_as(
            "SELECT * FROM orders WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()?;

        match order {
            Some(o) => Some(order_to_gql(o, pool.clone()).await),
            None => None,
        }
    }

    /// G05: Flags accessible without auth!
    async fn flags(&self, ctx: &Context<'_>) -> Vec<GqlFlag> {
        let pool = ctx.data::<DbPool>().unwrap();

        let flags: Vec<crate::db::Flag> = sqlx::query_as("SELECT * FROM flags")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

        flags.into_iter().map(|f| GqlFlag {
            id: f.id,
            vulnerability_id: f.vulnerability_id,
            flag_value: f.flag_value,
            hint: f.hint,
        }).collect()
    }

    /// G04: Field suggestions reveal schema when querying wrong field names
    async fn __debug(&self) -> String {
        "Debug endpoint - try querying non-existent fields to see suggestions".to_string()
    }
}

// Mutation root

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// G05: Mass assignment via GraphQL
    async fn create_user(&self, ctx: &Context<'_>, input: CreateUserInput) -> Option<GqlUser> {
        let pool = ctx.data::<DbPool>().unwrap();

        // G05: Role can be set by attacker
        let role = input.role.unwrap_or_else(|| "user".to_string());
        let password_hash = format!("$2b$12${}", input.password);

        let result = sqlx::query(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)"
        )
        .bind(&input.username)
        .bind(&input.email)
        .bind(&password_hash)
        .bind(&role)
        .execute(pool)
        .await
        .ok()?;

        let user_id = result.last_insert_rowid();

        let user: Option<crate::db::User> = sqlx::query_as(
            "SELECT * FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()?;

        user.map(|u| user_to_gql(u, pool.clone()))
    }

    /// G05: Can update any user
    async fn update_user(
        &self,
        ctx: &Context<'_>,
        id: i64,
        username: Option<String>,
        email: Option<String>,
        role: Option<String>,
    ) -> Option<GqlUser> {
        let pool = ctx.data::<DbPool>().unwrap();

        // G05: No auth check, can update any user including role
        if let Some(ref name) = username {
            let _ = sqlx::query("UPDATE users SET username = ? WHERE id = ?")
                .bind(name)
                .bind(id)
                .execute(pool)
                .await;
        }
        if let Some(ref mail) = email {
            let _ = sqlx::query("UPDATE users SET email = ? WHERE id = ?")
                .bind(mail)
                .bind(id)
                .execute(pool)
                .await;
        }
        if let Some(ref r) = role {
            let _ = sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                .bind(r)
                .bind(id)
                .execute(pool)
                .await;
        }

        let user: Option<crate::db::User> = sqlx::query_as(
            "SELECT * FROM users WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()?;

        user.map(|u| user_to_gql(u, pool.clone()))
    }

    /// G05: Can delete any user
    async fn delete_user(&self, ctx: &Context<'_>, id: i64) -> bool {
        let pool = ctx.data::<DbPool>().unwrap();

        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await
            .is_ok()
    }
}

// Helper functions

fn user_to_gql(user: crate::db::User, _pool: DbPool) -> GqlUser {
    GqlUser {
        id: user.id,
        username: user.username,
        email: user.email,
        ssn: user.ssn,
        credit_card: user.credit_card,
        role: user.role,
        orders: Vec::new(), // Lazy loaded
    }
}

fn product_to_gql(product: crate::db::Product) -> GqlProduct {
    GqlProduct {
        id: product.id,
        name: product.name,
        description: product.description,
        price: product.price,
        stock: product.stock,
        category: product.category,
    }
}

async fn order_to_gql(order: crate::db::Order, pool: DbPool) -> GqlOrder {
    let items: Vec<crate::db::OrderItem> = sqlx::query_as(
        "SELECT * FROM order_items WHERE order_id = ?"
    )
    .bind(order.id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let gql_items: Vec<GqlOrderItem> = items.into_iter().map(|item| {
        GqlOrderItem {
            id: item.id,
            product_id: item.product_id,
            quantity: item.quantity,
            price: item.price,
            product: None,
        }
    }).collect();

    GqlOrder {
        id: order.id,
        user_id: order.user_id,
        status: order.status,
        total: order.total,
        user: None,
        items: gql_items,
    }
}

pub type DojoSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn create_schema(pool: DbPool) -> DojoSchema {
    // G01: Introspection enabled
    // G02: No depth limit
    // G03: No complexity limit
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(pool)
        .finish()
}
