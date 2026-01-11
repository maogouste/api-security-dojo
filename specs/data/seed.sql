-- VulnAPI Seed Data
-- This SQL file contains the initial data for all implementations
-- Password hashes use MD5-crypt format for portability

-- Users table
INSERT INTO users (id, username, email, password_hash, role, is_active, ssn, credit_card, secret_note, api_key, created_at, updated_at) VALUES
(1, 'admin', 'admin@vulnapi.local', '$1$salt$hash_admin123', 'admin', 1, '123-45-6789', '4111-1111-1111-1111', 'VULNAPI{bola_user_data_exposed}', 'admin-api-key-12345', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 'john', 'john@example.com', '$1$salt$hash_password123', 'user', 1, '987-65-4321', '5500-0000-0000-0004', 'John''s private notes', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(3, 'jane', 'jane@example.com', '$1$salt$hash_jane2024', 'user', 1, '456-78-9012', '3400-0000-0000-009', 'Jane''s secret data', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(4, 'bob', 'bob@example.com', '$1$salt$hash_bob', 'user', 1, NULL, NULL, NULL, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(5, 'service_account', 'service@vulnapi.local', '$1$salt$hash_svc', 'superadmin', 1, NULL, NULL, 'Service account - do not delete', 'VULNAPI{jwt_weak_secret_cracked}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Products table
INSERT INTO products (id, name, description, price, stock, category, is_active, internal_notes, supplier_cost, created_at, updated_at) VALUES
(1, 'Laptop Pro X1', 'High-performance laptop for professionals', 1299.99, 50, 'Electronics', 1, 'VULNAPI{exposure_internal_data_leak}', 850.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 'Wireless Mouse', 'Ergonomic wireless mouse', 49.99, 200, 'Electronics', 1, 'Supplier: TechCorp, Margin: 60%', 20.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(3, 'USB-C Hub', '7-in-1 USB-C hub with HDMI', 79.99, 150, 'Electronics', 1, 'Best seller Q4 2024', 35.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(4, 'Mechanical Keyboard', 'RGB mechanical keyboard with Cherry MX switches', 149.99, 75, 'Electronics', 1, NULL, 80.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(5, '4K Monitor', '27-inch 4K IPS monitor', 399.99, 30, 'Electronics', 1, 'Discontinued model - clearance', 250.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(6, 'Secret Product', 'VULNAPI{sqli_database_dumped}', 9999.99, 1, 'Hidden', 0, 'This product should never be visible', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Flags table
INSERT INTO flags (id, challenge_id, flag_value, description, created_at) VALUES
(1, 'V01', 'VULNAPI{bola_user_data_exposed}', 'Found by accessing another user''s data via BOLA', CURRENT_TIMESTAMP),
(2, 'V02', 'VULNAPI{jwt_weak_secret_cracked}', 'Found by cracking the weak JWT secret', CURRENT_TIMESTAMP),
(3, 'V03', 'VULNAPI{exposure_internal_data_leak}', 'Found in excessive data exposure in API responses', CURRENT_TIMESTAMP),
(4, 'V04', 'VULNAPI{ratelimit_bruteforce_success}', 'Demonstrated by brute forcing login without rate limiting', CURRENT_TIMESTAMP),
(5, 'V05', 'VULNAPI{mass_assignment_privilege_escalation}', 'Found by escalating privileges via mass assignment', CURRENT_TIMESTAMP),
(6, 'V06', 'VULNAPI{sqli_database_dumped}', 'Found by exploiting SQL injection in product search', CURRENT_TIMESTAMP),
(7, 'V07', 'VULNAPI{cmd_injection_rce_achieved}', 'Found by achieving RCE via command injection', CURRENT_TIMESTAMP),
(8, 'V08', 'VULNAPI{misconfig_cors_headers_missing}', 'Identified by checking security headers and CORS config', CURRENT_TIMESTAMP),
(9, 'V09', 'VULNAPI{version_legacy_api_exposed}', 'Found by discovering and exploiting old API version', CURRENT_TIMESTAMP),
(10, 'V10', 'VULNAPI{logging_blind_attack_undetected}', 'Demonstrated by performing attacks without logging', CURRENT_TIMESTAMP);

-- Test credentials for implementations:
-- admin:admin123 (admin role)
-- john:password123 (user role)
-- jane:jane2024 (user role)
-- bob:bob (user role, weak password)
-- service_account:svc_password_2024 (superadmin role)
