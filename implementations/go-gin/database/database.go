// Package database handles database initialization and seeding
package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// InitDB initializes the database connection and schema
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./vulnapi.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	schema := `
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
	);
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
	);
	CREATE TABLE IF NOT EXISTS flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		challenge_id TEXT UNIQUE NOT NULL,
		flag_value TEXT NOT NULL,
		description TEXT
	);
	CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		status TEXT DEFAULT 'pending',
		total_amount REAL DEFAULT 0,
		shipping_address TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`
	DB.Exec(schema)

	// Seed if empty
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		SeedDatabase()
	}
}

// Close closes the database connection
func Close() {
	if DB != nil {
		DB.Close()
	}
}

// SeedDatabase populates the database with initial data
func SeedDatabase() {
	log.Println("[*] Seeding database...")

	// Users - VULNERABILITY: weak bcrypt cost
	users := []struct {
		username, email, password, role       string
		ssn, creditCard, secretNote, apiKey   *string
	}{
		{"admin", "admin@vulnapi.local", "admin123", "admin", strPtr("123-45-6789"), strPtr("4111-1111-1111-1111"), strPtr("VULNAPI{bola_user_data_exposed}"), strPtr("admin-api-key-12345")},
		{"john", "john@example.com", "password123", "user", strPtr("987-65-4321"), strPtr("5500-0000-0000-0004"), strPtr("John's private notes"), nil},
		{"jane", "jane@example.com", "jane2024", "user", strPtr("456-78-9012"), strPtr("3400-0000-0000-009"), strPtr("Jane's secret data"), nil},
		{"bob", "bob@example.com", "bob", "user", nil, nil, nil, nil},
		{"service_account", "service@vulnapi.local", "svc_password_2024", "superadmin", nil, nil, strPtr("Service account - do not delete"), strPtr("VULNAPI{jwt_weak_secret_cracked}")},
	}

	for _, u := range users {
		hash, _ := bcrypt.GenerateFromPassword([]byte(u.password), 4) // Weak cost
		DB.Exec(`INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			u.username, u.email, string(hash), u.role, u.ssn, u.creditCard, u.secretNote, u.apiKey)
	}

	// Products
	products := []struct {
		name, description string
		price             float64
		stock             int
		category          string
		isActive          int
		internalNotes     *string
		supplierCost      *float64
	}{
		{"Laptop Pro X1", "High-performance laptop", 1299.99, 50, "Electronics", 1, strPtr("VULNAPI{exposure_internal_data_leak}"), floatPtr(850.00)},
		{"Wireless Mouse", "Ergonomic wireless mouse", 49.99, 200, "Electronics", 1, strPtr("Supplier: TechCorp"), floatPtr(20.00)},
		{"USB-C Hub", "7-in-1 USB-C hub", 79.99, 150, "Electronics", 1, strPtr("Best seller Q4 2024"), floatPtr(35.00)},
		{"Mechanical Keyboard", "RGB mechanical keyboard", 149.99, 75, "Electronics", 1, nil, floatPtr(80.00)},
		{"4K Monitor", "27-inch 4K IPS monitor", 399.99, 30, "Electronics", 1, strPtr("Discontinued"), floatPtr(250.00)},
		{"Secret Product", "VULNAPI{sqli_database_dumped}", 9999.99, 1, "Hidden", 0, strPtr("Should never be visible"), nil},
	}

	for _, p := range products {
		DB.Exec(`INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.name, p.description, p.price, p.stock, p.category, p.isActive, p.internalNotes, p.supplierCost)
	}

	// Flags
	flags := []struct{ id, value, desc string }{
		{"V01", "VULNAPI{bola_user_data_exposed}", "Found by accessing another user's data via BOLA"},
		{"V02", "VULNAPI{jwt_weak_secret_cracked}", "Found by cracking the weak JWT secret"},
		{"V03", "VULNAPI{exposure_internal_data_leak}", "Found in excessive data exposure"},
		{"V04", "VULNAPI{ratelimit_bruteforce_success}", "Demonstrated by brute forcing login"},
		{"V05", "VULNAPI{mass_assignment_privilege_escalation}", "Found by escalating privileges via mass assignment"},
		{"V06", "VULNAPI{sqli_database_dumped}", "Found by exploiting SQL injection"},
		{"V07", "VULNAPI{cmd_injection_rce_achieved}", "Found by achieving RCE via command injection"},
		{"V08", "VULNAPI{misconfig_cors_headers_missing}", "Identified by checking security headers"},
		{"V09", "VULNAPI{version_legacy_api_exposed}", "Found by discovering old API version"},
		{"V10", "VULNAPI{logging_blind_attack_undetected}", "Demonstrated by performing attacks without logging"},
		{"G01", "VULNAPI{graphql_introspection_schema_leaked}", "Found by using GraphQL introspection"},
		{"G02", "VULNAPI{graphql_depth_resource_exhaustion}", "Demonstrated by exploiting unlimited query depth"},
		{"G03", "VULNAPI{graphql_batch_rate_limit_bypass}", "Found by batching multiple operations"},
		{"G04", "VULNAPI{graphql_suggestions_field_enumeration}", "Found by using error messages to enumerate fields"},
		{"G05", "VULNAPI{graphql_authz_sensitive_data_exposed}", "Found by accessing sensitive data without auth"},
	}

	for _, f := range flags {
		DB.Exec(`INSERT INTO flags (challenge_id, flag_value, description) VALUES (?, ?, ?)`, f.id, f.value, f.desc)
	}

	// Orders (for G02 depth testing)
	orders := []struct {
		userId          int
		status          string
		total           float64
		shippingAddress string
		notes           string
	}{
		{1, "completed", 1349.98, "123 Admin St, Server City", "Admin's test order"},
		{2, "pending", 199.98, "456 User Ave, Client Town", "John's order - sensitive shipping info"},
		{2, "shipped", 79.99, "456 User Ave, Client Town", "John's second order"},
		{3, "completed", 549.98, "789 Jane Ln, Data Village", "VULNAPI{graphql_depth_resource_exhaustion}"},
	}

	for _, o := range orders {
		DB.Exec(`INSERT INTO orders (user_id, status, total_amount, shipping_address, notes) VALUES (?, ?, ?, ?, ?)`,
			o.userId, o.status, o.total, o.shippingAddress, o.notes)
	}

	log.Println("[*] Database seeded successfully!")
}

func strPtr(s string) *string     { return &s }
func floatPtr(f float64) *float64 { return &f }
