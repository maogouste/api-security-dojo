//! Documentation handlers for vulnerability explanations.
//!
//! Provides endpoints to access detailed documentation about each vulnerability.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Get the current mode from environment
fn get_mode() -> String {
    std::env::var("DOJO_MODE").unwrap_or_else(|_| "challenge".to_string())
}

/// Load vulnerabilities from JSON file
fn load_vulnerabilities() -> Vec<serde_json::Value> {
    let path = "vulnerabilities.json";
    match fs::read_to_string(path) {
        Ok(content) => {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(vulns) = doc.get("vulnerabilities").and_then(|v| v.as_array()) {
                    return vulns.clone();
                }
            }
            vec![]
        }
        Err(_) => vec![],
    }
}

/// Key differences for each vulnerability (educational summaries)
fn get_key_differences() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    map.insert("V01", "Add authorization check: verify user owns the resource or has admin role");
    map.insert("V02", "Use strong secrets from environment + generic error messages");
    map.insert("V03", "Use response models (DTOs) to filter sensitive fields");
    map.insert("V04", "Implement rate limiting with sliding window or token bucket");
    map.insert("V05", "Whitelist allowed fields, never bind request directly to model");
    map.insert("V06", "Use parameterized queries, never concatenate user input into SQL");
    map.insert("V07", "Validate input strictly, use safe APIs instead of shell execution");
    map.insert("V08", "Configure CORS properly, disable debug endpoints in production");
    map.insert("V09", "Deprecate and remove old API versions, apply same security controls");
    map.insert("V10", "Log security events, implement alerting on suspicious patterns");
    map.insert("G01", "Disable introspection in production");
    map.insert("G02", "Set query depth limit: max_depth=10");
    map.insert("G03", "Limit batch size and implement query cost analysis");
    map.insert("G04", "Disable field suggestions in production errors");
    map.insert("G05", "Add authorization checks to all resolvers");
    map
}

#[derive(Serialize)]
struct ModeResponse {
    mode: String,
    documentation_enabled: bool,
    description: String,
}

/// GET /api/docs/mode - Get current API mode
pub async fn docs_mode() -> HttpResponse {
    let mode = get_mode();
    let description = if mode == "documentation" {
        "Documentation mode: Full exploitation details and remediation"
    } else {
        "Challenge mode: Limited information, find vulnerabilities yourself"
    };

    HttpResponse::Ok().json(ModeResponse {
        documentation_enabled: mode == "documentation",
        mode,
        description: description.to_string(),
    })
}

#[derive(Serialize)]
struct StatsResponse {
    total: usize,
    by_severity: HashMap<String, i32>,
    by_category: HashMap<String, i32>,
    rest_api: i32,
    graphql: i32,
}

/// GET /api/docs/stats - Get vulnerability statistics
pub async fn docs_stats() -> HttpResponse {
    let vulns = load_vulnerabilities();
    let mut by_severity: HashMap<String, i32> = HashMap::new();
    let mut by_category: HashMap<String, i32> = HashMap::new();
    let mut rest_api = 0;
    let mut graphql = 0;

    for v in &vulns {
        if let Some(severity) = v.get("severity").and_then(|s| s.as_str()) {
            *by_severity.entry(severity.to_string()).or_insert(0) += 1;
        }
        if let Some(category) = v.get("category").and_then(|c| c.as_str()) {
            *by_category.entry(category.to_string()).or_insert(0) += 1;
        }
        if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
            if id.starts_with('V') {
                rest_api += 1;
            } else if id.starts_with('G') {
                graphql += 1;
            }
        }
    }

    HttpResponse::Ok().json(StatsResponse {
        total: vulns.len(),
        by_severity,
        by_category,
        rest_api,
        graphql,
    })
}

#[derive(Serialize)]
struct CategoryInfo {
    name: String,
    count: i32,
    vulnerabilities: Vec<String>,
}

/// GET /api/docs/categories - List vulnerability categories
pub async fn docs_categories() -> HttpResponse {
    let vulns = load_vulnerabilities();
    let mut categories: HashMap<String, CategoryInfo> = HashMap::new();

    for v in &vulns {
        if let (Some(cat), Some(id)) = (
            v.get("category").and_then(|c| c.as_str()),
            v.get("id").and_then(|i| i.as_str()),
        ) {
            let entry = categories.entry(cat.to_string()).or_insert_with(|| CategoryInfo {
                name: cat.to_string(),
                count: 0,
                vulnerabilities: vec![],
            });
            entry.count += 1;
            entry.vulnerabilities.push(id.to_string());
        }
    }

    let result: Vec<CategoryInfo> = categories.into_values().collect();
    HttpResponse::Ok().json(result)
}

#[derive(Deserialize)]
pub struct VulnQuery {
    category: Option<String>,
    severity: Option<String>,
}

#[derive(Serialize)]
struct VulnSummary {
    id: String,
    name: String,
    category: String,
    severity: String,
    owasp: String,
    cwe: String,
    description: String,
}

/// GET /api/docs/vulnerabilities - List vulnerabilities
pub async fn docs_vulnerabilities(query: web::Query<VulnQuery>) -> HttpResponse {
    let vulns = load_vulnerabilities();
    let mut result = vec![];

    for v in &vulns {
        let cat = v.get("category").and_then(|c| c.as_str()).unwrap_or("");
        let sev = v.get("severity").and_then(|s| s.as_str()).unwrap_or("");

        if let Some(ref qcat) = query.category {
            if cat != qcat {
                continue;
            }
        }
        if let Some(ref qsev) = query.severity {
            if sev != qsev {
                continue;
            }
        }

        result.push(VulnSummary {
            id: v.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string(),
            name: v.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            category: cat.to_string(),
            severity: sev.to_string(),
            owasp: v.get("owasp").and_then(|o| o.as_str()).unwrap_or("").to_string(),
            cwe: v.get("cwe").and_then(|c| c.as_str()).unwrap_or("").to_string(),
            description: v.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
        });
    }

    HttpResponse::Ok().json(result)
}

/// GET /api/docs/vulnerabilities/{id} - Get specific vulnerability details
pub async fn docs_vulnerability(path: web::Path<String>) -> HttpResponse {
    let mode = get_mode();
    if mode != "documentation" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Documentation mode is disabled",
            "message": "Set DOJO_MODE=documentation to access vulnerability details",
            "current_mode": mode
        }));
    }

    let id = path.into_inner();
    let vulns = load_vulnerabilities();

    for v in &vulns {
        if let Some(vid) = v.get("id").and_then(|i| i.as_str()) {
            if vid == id {
                return HttpResponse::Ok().json(v);
            }
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "detail": format!("Vulnerability {} not found", id)
    }))
}

#[derive(Serialize)]
struct CompareListItem {
    id: String,
    name: String,
    key_difference: String,
}

/// GET /api/docs/compare - List all code comparisons
pub async fn docs_compare_list() -> HttpResponse {
    let vulns = load_vulnerabilities();
    let key_diffs = get_key_differences();
    let mut result = vec![];

    for v in &vulns {
        let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("");
        let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let key_diff = key_diffs.get(id).copied().unwrap_or("");

        result.push(CompareListItem {
            id: id.to_string(),
            name: name.to_string(),
            key_difference: key_diff.to_string(),
        });
    }

    HttpResponse::Ok().json(result)
}

#[derive(Serialize)]
struct CompareResponse {
    id: String,
    name: String,
    vulnerable_code: serde_json::Value,
    secure_code: serde_json::Value,
    key_difference: String,
    remediation: serde_json::Value,
    owasp: String,
    cwe: String,
}

/// GET /api/docs/compare/{id} - Compare vulnerable vs secure code
/// Available in BOTH challenge and documentation modes
pub async fn docs_compare(path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let vulns = load_vulnerabilities();
    let key_diffs = get_key_differences();

    for v in &vulns {
        if let Some(vid) = v.get("id").and_then(|i| i.as_str()) {
            if vid == id {
                let key_diff = key_diffs.get(id.as_str()).copied().unwrap_or("See secure_code for the fix");

                return HttpResponse::Ok().json(CompareResponse {
                    id: id.clone(),
                    name: v.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                    vulnerable_code: v.get("vulnerable_code").cloned().unwrap_or(serde_json::Value::Null),
                    secure_code: v.get("secure_code").cloned().unwrap_or(serde_json::Value::Null),
                    key_difference: key_diff.to_string(),
                    remediation: v.get("remediation").cloned().unwrap_or(serde_json::Value::Null),
                    owasp: v.get("owasp").and_then(|o| o.as_str()).unwrap_or("").to_string(),
                    cwe: v.get("cwe").and_then(|c| c.as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "detail": format!("Vulnerability {} not found", id)
    }))
}
