//! Tool endpoints
//!
//! Vulnerabilities:
//! - V07: Command Injection in ping

use actix_web::{web, HttpResponse};
use std::process::Command;
use crate::db::{PingRequest, PingResponse, ErrorResponse};

/// V07: Command Injection - Ping endpoint
/// User input is directly passed to shell command
pub async fn ping(
    body: web::Json<PingRequest>,
) -> HttpResponse {
    let host = &body.host;

    // V07: Command Injection - user input passed directly to shell
    // Example payloads:
    // - "127.0.0.1; cat /etc/passwd"
    // - "127.0.0.1 && whoami"
    // - "127.0.0.1 | id"

    #[cfg(target_os = "windows")]
    let output = Command::new("cmd")
        .args(["/C", &format!("ping -n 1 {}", host)])
        .output();

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh")
        .args(["-c", &format!("ping -c 1 {}", host)])
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{}{}", stdout, stderr);

            HttpResponse::Ok().json(PingResponse {
                output: combined,
                host: host.clone(),
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Command execution failed".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}

/// V07: Alternative command injection via DNS lookup
pub async fn dns_lookup(
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let domain = query.get("domain").cloned().unwrap_or_default();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Missing domain parameter".to_string(),
            detail: None,
        });
    }

    // V07: Command Injection
    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh")
        .args(["-c", &format!("nslookup {}", domain)])
        .output();

    #[cfg(target_os = "windows")]
    let output = Command::new("cmd")
        .args(["/C", &format!("nslookup {}", domain)])
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            HttpResponse::Ok().json(serde_json::json!({
                "domain": domain,
                "output": format!("{}{}", stdout, stderr)
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "DNS lookup failed".to_string(),
            detail: Some(e.to_string()),
        }),
    }
}

/// Debug endpoint - V08: Security Misconfiguration
pub async fn debug_info() -> HttpResponse {
    // V08: Exposing sensitive debug information
    HttpResponse::Ok().json(serde_json::json!({
        "debug": true,
        "environment": std::env::var("DOJO_MODE").unwrap_or_else(|_| "challenge".to_string()),
        "database_url": std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:./dojo.db".to_string()),
        "jwt_secret": "super_secret_key_123",
        "rust_version": env!("CARGO_PKG_VERSION"),
        "env_vars": std::env::vars().collect::<Vec<_>>()
    }))
}
