package com.vulnapi.service;

import jakarta.annotation.PostConstruct;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Database initialization and seeding service.
 */
@Service
public class DatabaseInitializer {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder;

    public DatabaseInitializer(JdbcTemplate jdbc, BCryptPasswordEncoder encoder) {
        this.jdbc = jdbc;
        this.encoder = encoder;
    }

    @PostConstruct
    public void init() {
        initDatabase();
        System.out.println("""

            ╔═══════════════════════════════════════════════════════════╗
            ║                                                           ║
            ║   VulnAPI - Java/Spring Boot Implementation               ║
            ║   ⚠️  WARNING: Intentionally Vulnerable API               ║
            ║                                                           ║
            ║   Server running on http://localhost:3004                 ║
            ║                                                           ║
            ╚═══════════════════════════════════════════════════════════╝
            """);
    }

    private void initDatabase() {
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                ssn TEXT,
                credit_card TEXT,
                secret_note TEXT,
                api_key TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                stock INTEGER DEFAULT 0,
                category TEXT,
                is_active INTEGER DEFAULT 1,
                internal_notes TEXT,
                supplier_cost REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT UNIQUE NOT NULL,
                flag_value TEXT NOT NULL,
                description TEXT
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                total_amount REAL DEFAULT 0,
                shipping_address TEXT,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """);

        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
        if (count == 0) seedDatabase();
    }

    private void seedDatabase() {
        System.out.println("[*] Seeding database...");

        Object[][] users = {
            {"admin", "admin@vulnapi.local", "admin123", "admin", "123-45-6789", "4111-1111-1111-1111", "VULNAPI{bola_user_data_exposed}", "admin-api-key-12345"},
            {"john", "john@example.com", "password123", "user", "987-65-4321", "5500-0000-0000-0004", "John's private notes", null},
            {"jane", "jane@example.com", "jane2024", "user", "456-78-9012", "3400-0000-0000-009", "Jane's secret data", null},
            {"bob", "bob@example.com", "bob", "user", null, null, null, null},
            {"service_account", "service@vulnapi.local", "svc_password_2024", "superadmin", null, null, "Service account", "VULNAPI{jwt_weak_secret_cracked}"},
        };

        for (Object[] u : users) {
            jdbc.update("INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                u[0], u[1], encoder.encode((String)u[2]), u[3], u[4], u[5], u[6], u[7]);
        }

        Object[][] products = {
            {"Laptop Pro X1", "High-performance laptop", 1299.99, 50, "Electronics", 1, "VULNAPI{exposure_internal_data_leak}", 850.00},
            {"Wireless Mouse", "Ergonomic wireless mouse", 49.99, 200, "Electronics", 1, "Supplier: TechCorp", 20.00},
            {"USB-C Hub", "7-in-1 USB-C hub", 79.99, 150, "Electronics", 1, "Best seller Q4 2024", 35.00},
            {"Mechanical Keyboard", "RGB mechanical keyboard", 149.99, 75, "Electronics", 1, null, 80.00},
            {"4K Monitor", "27-inch 4K IPS monitor", 399.99, 30, "Electronics", 1, "Discontinued", 250.00},
            {"Secret Product", "VULNAPI{sqli_database_dumped}", 9999.99, 1, "Hidden", 0, "Should never be visible", null},
        };

        for (Object[] p : products) {
            jdbc.update("INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        }

        String[][] flags = {
            {"V01", "VULNAPI{bola_user_data_exposed}", "BOLA vulnerability"},
            {"V02", "VULNAPI{jwt_weak_secret_cracked}", "Weak JWT secret"},
            {"V03", "VULNAPI{exposure_internal_data_leak}", "Data exposure"},
            {"V04", "VULNAPI{ratelimit_bruteforce_success}", "No rate limiting"},
            {"V05", "VULNAPI{mass_assignment_privilege_escalation}", "Mass assignment"},
            {"V06", "VULNAPI{sqli_database_dumped}", "SQL injection"},
            {"V07", "VULNAPI{cmd_injection_rce_achieved}", "Command injection"},
            {"V08", "VULNAPI{misconfig_cors_headers_missing}", "Security misconfiguration"},
            {"V09", "VULNAPI{version_legacy_api_exposed}", "Legacy API exposed"},
            {"V10", "VULNAPI{logging_blind_attack_undetected}", "Insufficient logging"},
            {"G01", "VULNAPI{graphql_introspection_schema_leaked}", "GraphQL introspection"},
            {"G02", "VULNAPI{graphql_depth_resource_exhaustion}", "Query depth DoS"},
            {"G03", "VULNAPI{graphql_batch_rate_limit_bypass}", "Batching attacks"},
            {"G04", "VULNAPI{graphql_suggestions_field_enumeration}", "Field suggestions"},
            {"G05", "VULNAPI{graphql_authz_sensitive_data_exposed}", "Auth bypass"},
        };

        for (String[] f : flags) {
            jdbc.update("INSERT INTO flags (challenge_id, flag_value, description) VALUES (?, ?, ?)", f[0], f[1], f[2]);
        }

        Object[][] orders = {
            {1, "completed", 1349.98, "123 Admin St, Server City", "Admin's test order"},
            {2, "pending", 199.98, "456 User Ave, Client Town", "John's order - sensitive shipping info"},
            {2, "shipped", 79.99, "456 User Ave, Client Town", "John's second order"},
            {3, "completed", 549.98, "789 Jane Ln, Data Village", "VULNAPI{graphql_depth_resource_exhaustion}"},
        };

        for (Object[] o : orders) {
            jdbc.update("INSERT INTO orders (user_id, status, total_amount, shipping_address, notes) VALUES (?, ?, ?, ?, ?)",
                o[0], o[1], o[2], o[3], o[4]);
        }

        System.out.println("[*] Database seeded successfully!");
    }
}
