// VulnAPI - Go/Gin Implementation
//
// Deliberately vulnerable API for security learning.
// WARNING: This API contains intentional security vulnerabilities.
// Do NOT deploy in production.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// VULNERABILITY V02: Weak secret key
var jwtSecret = []byte("secret123")

var mode = getEnv("VULNAPI_MODE", "challenge")

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// User model
type User struct {
	ID           int     `json:"id"`
	Username     string  `json:"username"`
	Email        string  `json:"email"`
	PasswordHash string  `json:"password_hash,omitempty"`
	Role         string  `json:"role"`
	IsActive     bool    `json:"is_active"`
	SSN          *string `json:"ssn"`
	CreditCard   *string `json:"credit_card"`
	SecretNote   *string `json:"secret_note"`
	APIKey       *string `json:"api_key"`
	CreatedAt    string  `json:"created_at"`
}

// Product model
type Product struct {
	ID            int      `json:"id"`
	Name          string   `json:"name"`
	Description   *string  `json:"description"`
	Price         float64  `json:"price"`
	Stock         int      `json:"stock"`
	Category      *string  `json:"category"`
	IsActive      bool     `json:"is_active"`
	InternalNotes *string  `json:"internal_notes"`
	SupplierCost  *float64 `json:"supplier_cost"`
	CreatedAt     string   `json:"created_at"`
}

// Flag model
type Flag struct {
	ID          int    `json:"id"`
	ChallengeID string `json:"challenge_id"`
	FlagValue   string `json:"flag_value"`
	Description string `json:"description"`
}

func main() {
	initDB()
	defer db.Close()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// VULNERABILITY V08: CORS misconfiguration
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Root
	r.GET("/", rootHandler)
	r.GET("/health", healthHandler)

	// Auth routes
	r.POST("/api/register", registerHandler)
	r.POST("/api/login", loginHandler)
	r.GET("/api/me", authMiddleware(), meHandler)

	// Users routes
	r.GET("/api/users", optionalAuth(), listUsersHandler)
	r.GET("/api/users/:id", optionalAuth(), getUserHandler)
	r.PUT("/api/users/:id", authMiddleware(), updateUserHandler)
	r.DELETE("/api/users/:id", authMiddleware(), deleteUserHandler)

	// Legacy API V1 - VULNERABILITY V09
	r.GET("/api/v1/users", listUsersV1Handler)
	r.GET("/api/v1/users/:id", getUserV1Handler)

	// Products routes
	r.GET("/api/products", listProductsHandler)
	r.GET("/api/products/:id", getProductHandler)

	// Tools routes
	r.POST("/api/tools/ping", authMiddleware(), pingHandler)
	r.POST("/api/tools/dns", authMiddleware(), dnsHandler)
	r.GET("/api/tools/debug", debugHandler)

	// Flags routes
	r.GET("/api/challenges", listChallengesHandler)
	r.POST("/api/flags/submit", authMiddleware(), submitFlagHandler)

	// Docs routes
	r.GET("/api/docs/mode", docsModeHandler)
	r.GET("/api/docs/stats", docsStatsHandler)
	r.GET("/api/docs/categories", docsCategoriesHandler)
	r.GET("/api/docs/vulnerabilities", docsVulnerabilitiesHandler)
	r.GET("/api/docs/vulnerabilities/:id", docsVulnerabilityHandler)

	// GraphQL
	r.Any("/graphql", graphqlHandler())
	r.Any("/graphql/", graphqlHandler())

	port := getEnv("PORT", "3002")
	fmt.Printf(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   VulnAPI - Go/Gin Implementation                         ║
║   ⚠️  WARNING: Intentionally Vulnerable API               ║
║                                                           ║
║   Mode: %-49s║
║   Server running on http://localhost:%-20s║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`, mode, port)

	log.Fatal(r.Run(":" + port))
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./vulnapi.db")
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
	`
	db.Exec(schema)

	// Seed if empty
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		seedDatabase()
	}
}

func seedDatabase() {
	log.Println("[*] Seeding database...")

	// Users - VULNERABILITY: weak bcrypt cost
	users := []struct {
		username, email, password, role string
		ssn, creditCard, secretNote, apiKey *string
	}{
		{"admin", "admin@vulnapi.local", "admin123", "admin", strPtr("123-45-6789"), strPtr("4111-1111-1111-1111"), strPtr("VULNAPI{bola_user_data_exposed}"), strPtr("admin-api-key-12345")},
		{"john", "john@example.com", "password123", "user", strPtr("987-65-4321"), strPtr("5500-0000-0000-0004"), strPtr("John's private notes"), nil},
		{"jane", "jane@example.com", "jane2024", "user", strPtr("456-78-9012"), strPtr("3400-0000-0000-009"), strPtr("Jane's secret data"), nil},
		{"bob", "bob@example.com", "bob", "user", nil, nil, nil, nil},
		{"service_account", "service@vulnapi.local", "svc_password_2024", "superadmin", nil, nil, strPtr("Service account - do not delete"), strPtr("VULNAPI{jwt_weak_secret_cracked}")},
	}

	for _, u := range users {
		hash, _ := bcrypt.GenerateFromPassword([]byte(u.password), 4) // Weak cost
		db.Exec(`INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
		db.Exec(`INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
		db.Exec(`INSERT INTO flags (challenge_id, flag_value, description) VALUES (?, ?, ?)`, f.id, f.value, f.desc)
	}

	log.Println("[*] Database seeded successfully!")
}

func strPtr(s string) *string    { return &s }
func floatPtr(f float64) *float64 { return &f }

// JWT helpers
func createToken(user *User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":     user.Username,
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func parseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(401, gin.H{"detail": "Not authenticated"})
			c.Abort()
			return
		}
		claims, err := parseToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			c.JSON(401, gin.H{"detail": "Invalid token"})
			c.Abort()
			return
		}
		userID := int(claims["user_id"].(float64))
		var user User
		err = db.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", userID).
			Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey)
		if err != nil {
			c.JSON(401, gin.H{"detail": "User not found"})
			c.Abort()
			return
		}
		c.Set("user", &user)
		c.Next()
	}
}

func optionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			if claims, err := parseToken(strings.TrimPrefix(auth, "Bearer ")); err == nil {
				userID := int(claims["user_id"].(float64))
				var user User
				if err := db.QueryRow("SELECT id, username, email, role FROM users WHERE id = ?", userID).
					Scan(&user.ID, &user.Username, &user.Email, &user.Role); err == nil {
					c.Set("user", &user)
				}
			}
		}
		c.Next()
	}
}

// Handlers
func rootHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"name":           "VulnAPI",
		"version":        "0.2.0",
		"mode":           mode,
		"implementation": "Go/Gin",
		"message":        "Welcome to VulnAPI - A deliberately vulnerable API",
	})
}

func healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "healthy", "implementation": "go-gin"})
}

// Auth handlers
func registerHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "Invalid request"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 4)
	result, err := db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')`,
		req.Username, req.Email, string(hash))
	if err != nil {
		c.JSON(400, gin.H{"detail": "Username or email already exists"})
		return
	}
	id, _ := result.LastInsertId()
	c.JSON(201, gin.H{"id": id, "username": req.Username, "email": req.Email, "role": "user"})
}

func loginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "Invalid request"})
		return
	}
	var user User
	var hash string
	err := db.QueryRow("SELECT id, username, email, password_hash, role FROM users WHERE username = ?", req.Username).
		Scan(&user.ID, &user.Username, &user.Email, &hash, &user.Role)
	if err != nil {
		// VULNERABILITY: User enumeration
		c.JSON(401, gin.H{"detail": "User not found"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(401, gin.H{"detail": "Incorrect password"})
		return
	}
	token, _ := createToken(&user)
	c.JSON(200, gin.H{"access_token": token, "token_type": "bearer", "user_id": user.ID, "role": user.Role})
}

func meHandler(c *gin.Context) {
	user := c.MustGet("user").(*User)
	c.JSON(200, user)
}

// User handlers
func listUsersHandler(c *gin.Context) {
	rows, _ := db.Query("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users")
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.IsActive, &u.SSN, &u.CreditCard, &u.SecretNote, &u.APIKey, &u.CreatedAt)
		users = append(users, u)
	}
	c.JSON(200, users)
}

func getUserHandler(c *gin.Context) {
	id := c.Param("id")
	var user User
	// VULNERABILITY V01: No authorization check
	err := db.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey, &user.CreatedAt)
	if err != nil {
		c.JSON(404, gin.H{"detail": "User not found"})
		return
	}
	c.JSON(200, user)
}

func updateUserHandler(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	c.BindJSON(&updates)

	// VULNERABILITY V05: Mass assignment
	for field, value := range updates {
		if field == "password" {
			hash, _ := bcrypt.GenerateFromPassword([]byte(value.(string)), 4)
			db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
		} else {
			db.Exec(fmt.Sprintf("UPDATE users SET %s = ? WHERE id = ?", field), value, id)
		}
	}

	var user User
	db.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey)
	c.JSON(200, user)
}

func deleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	db.Exec("DELETE FROM users WHERE id = ?", id)
	c.JSON(200, gin.H{"message": "User deleted"})
}

// Legacy API - VULNERABILITY V09
func listUsersV1Handler(c *gin.Context) {
	rows, _ := db.Query("SELECT id, username, email, password_hash, role, ssn, credit_card, secret_note, api_key FROM users")
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.SSN, &u.CreditCard, &u.SecretNote, &u.APIKey)
		users = append(users, u)
	}
	c.JSON(200, users)
}

func getUserV1Handler(c *gin.Context) {
	id := c.Param("id")
	var user User
	db.QueryRow("SELECT id, username, email, password_hash, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey)
	c.JSON(200, user)
}

// Products handlers
func listProductsHandler(c *gin.Context) {
	search := c.Query("search")
	var rows *sql.Rows
	if search != "" {
		// VULNERABILITY V06: SQL Injection
		query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%' OR description LIKE '%%%s%%'", search, search)
		rows, _ = db.Query(query)
	} else {
		rows, _ = db.Query("SELECT * FROM products WHERE is_active = 1")
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.Category, &p.IsActive, &p.InternalNotes, &p.SupplierCost, &p.CreatedAt)
		products = append(products, p)
	}
	c.JSON(200, products)
}

func getProductHandler(c *gin.Context) {
	id := c.Param("id")
	var p Product
	db.QueryRow("SELECT * FROM products WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.Category, &p.IsActive, &p.InternalNotes, &p.SupplierCost, &p.CreatedAt)
	c.JSON(200, p)
}

// Tools handlers
func pingHandler(c *gin.Context) {
	var req struct {
		Host string `json:"host"`
	}
	c.BindJSON(&req)

	// VULNERABILITY V07: Command injection
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", req.Host))
	output, err := cmd.CombinedOutput()

	c.JSON(200, gin.H{
		"success": err == nil,
		"command": fmt.Sprintf("ping -c 1 %s", req.Host),
		"output":  string(output),
	})
}

func dnsHandler(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	c.BindJSON(&req)

	// VULNERABILITY V07: Command injection
	cmd := exec.Command("sh", "-c", fmt.Sprintf("nslookup %s", req.Domain))
	output, _ := cmd.CombinedOutput()

	c.JSON(200, gin.H{"domain": req.Domain, "output": string(output)})
}

func debugHandler(c *gin.Context) {
	// VULNERABILITY V08: Exposes sensitive debug info
	c.JSON(200, gin.H{
		"go_version": "go1.21",
		"env_vars":   os.Environ(),
		"cwd":        func() string { d, _ := os.Getwd(); return d }(),
	})
}

// Flags handlers
func listChallengesHandler(c *gin.Context) {
	rows, _ := db.Query("SELECT challenge_id, description FROM flags")
	defer rows.Close()
	var challenges []gin.H
	for rows.Next() {
		var id, desc string
		rows.Scan(&id, &desc)
		cat := "rest"
		if strings.HasPrefix(id, "G") {
			cat = "graphql"
		}
		challenges = append(challenges, gin.H{"id": id, "description": desc, "category": cat})
	}
	c.JSON(200, challenges)
}

func submitFlagHandler(c *gin.Context) {
	var req struct {
		Flag string `json:"flag"`
	}
	c.BindJSON(&req)

	var f Flag
	err := db.QueryRow("SELECT challenge_id, description FROM flags WHERE flag_value = ?", req.Flag).Scan(&f.ChallengeID, &f.Description)
	if err != nil {
		c.JSON(200, gin.H{"success": false, "message": "Invalid flag"})
		return
	}
	c.JSON(200, gin.H{"success": true, "message": fmt.Sprintf("Congratulations! You solved challenge %s!", f.ChallengeID), "challenge_id": f.ChallengeID})
}

// Docs handlers
func docsModeHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"mode":                  mode,
		"documentation_enabled": mode == "documentation",
		"description": func() string {
			if mode == "documentation" {
				return "Documentation mode: Full exploitation details and remediation"
			}
			return "Challenge mode: Limited information, find vulnerabilities yourself"
		}(),
	})
}

func docsStatsHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	stats := gin.H{
		"total":       len(vulns),
		"by_severity": map[string]int{},
		"by_category": map[string]int{},
		"rest_api":    0,
		"graphql":     0,
	}

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		stats["by_severity"].(map[string]int)[vm["severity"].(string)]++
		stats["by_category"].(map[string]int)[vm["category"].(string)]++
		if strings.HasPrefix(vm["id"].(string), "V") {
			stats["rest_api"] = stats["rest_api"].(int) + 1
		} else {
			stats["graphql"] = stats["graphql"].(int) + 1
		}
	}
	c.JSON(200, stats)
}

func docsCategoriesHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	categories := map[string]gin.H{}

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		cat := vm["category"].(string)
		if _, ok := categories[cat]; !ok {
			categories[cat] = gin.H{"name": cat, "count": 0, "vulnerabilities": []string{}}
		}
		categories[cat]["count"] = categories[cat]["count"].(int) + 1
		categories[cat]["vulnerabilities"] = append(categories[cat]["vulnerabilities"].([]string), vm["id"].(string))
	}

	var result []gin.H
	for _, v := range categories {
		result = append(result, v)
	}
	c.JSON(200, result)
}

func docsVulnerabilitiesHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	category := c.Query("category")
	severity := c.Query("severity")

	var result []gin.H
	for _, v := range vulns {
		vm := v.(map[string]interface{})
		if category != "" && vm["category"].(string) != category {
			continue
		}
		if severity != "" && vm["severity"].(string) != severity {
			continue
		}
		result = append(result, gin.H{
			"id":          vm["id"],
			"name":        vm["name"],
			"category":    vm["category"],
			"severity":    vm["severity"],
			"owasp":       vm["owasp"],
			"cwe":         vm["cwe"],
			"description": vm["description"],
		})
	}
	c.JSON(200, result)
}

func docsVulnerabilityHandler(c *gin.Context) {
	if mode != "documentation" {
		c.JSON(403, gin.H{
			"error":        "Documentation mode is disabled",
			"message":      "Set VULNAPI_MODE=documentation to access vulnerability details",
			"current_mode": mode,
		})
		return
	}

	id := c.Param("id")
	vulns := loadVulnerabilities()

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		if vm["id"].(string) == id {
			c.JSON(200, vm)
			return
		}
	}
	c.JSON(404, gin.H{"detail": fmt.Sprintf("Vulnerability %s not found", id)})
}

func loadVulnerabilities() []interface{} {
	data, err := os.ReadFile("vulnerabilities.json")
	if err != nil {
		return []interface{}{}
	}
	var doc map[string]interface{}
	json.Unmarshal(data, &doc)
	if vulns, ok := doc["vulnerabilities"].([]interface{}); ok {
		return vulns
	}
	return []interface{}{}
}

// GraphQL
func graphqlHandler() gin.HandlerFunc {
	userType := graphql.NewObject(graphql.ObjectConfig{
		Name: "User",
		Fields: graphql.Fields{
			"id":         &graphql.Field{Type: graphql.Int},
			"username":   &graphql.Field{Type: graphql.String},
			"email":      &graphql.Field{Type: graphql.String},
			"role":       &graphql.Field{Type: graphql.String},
			"ssn":        &graphql.Field{Type: graphql.String},
			"creditCard": &graphql.Field{Type: graphql.String},
			"secretNote": &graphql.Field{Type: graphql.String},
			"apiKey":     &graphql.Field{Type: graphql.String},
		},
	})

	productType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Product",
		Fields: graphql.Fields{
			"id":            &graphql.Field{Type: graphql.Int},
			"name":          &graphql.Field{Type: graphql.String},
			"description":   &graphql.Field{Type: graphql.String},
			"price":         &graphql.Field{Type: graphql.Float},
			"stock":         &graphql.Field{Type: graphql.Int},
			"category":      &graphql.Field{Type: graphql.String},
			"internalNotes": &graphql.Field{Type: graphql.String},
			"supplierCost":  &graphql.Field{Type: graphql.Float},
		},
	})

	authPayloadType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AuthPayload",
		Fields: graphql.Fields{
			"accessToken": &graphql.Field{Type: graphql.String},
			"tokenType":   &graphql.Field{Type: graphql.String},
			"userId":      &graphql.Field{Type: graphql.Int},
			"role":        &graphql.Field{Type: graphql.String},
		},
	})

	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"users": &graphql.Field{
				Type: graphql.NewList(userType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					rows, _ := db.Query("SELECT id, username, email, role, ssn, credit_card, secret_note, api_key FROM users")
					defer rows.Close()
					var users []map[string]interface{}
					for rows.Next() {
						var id int
						var username, email, role string
						var ssn, creditCard, secretNote, apiKey *string
						rows.Scan(&id, &username, &email, &role, &ssn, &creditCard, &secretNote, &apiKey)
						users = append(users, map[string]interface{}{
							"id": id, "username": username, "email": email, "role": role,
							"ssn": ssn, "creditCard": creditCard, "secretNote": secretNote, "apiKey": apiKey,
						})
					}
					return users, nil
				},
			},
			"user": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Int)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id := p.Args["id"].(int)
					var username, email, role string
					var ssn, creditCard, secretNote, apiKey *string
					db.QueryRow("SELECT username, email, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
						Scan(&username, &email, &role, &ssn, &creditCard, &secretNote, &apiKey)
					return map[string]interface{}{
						"id": id, "username": username, "email": email, "role": role,
						"ssn": ssn, "creditCard": creditCard, "secretNote": secretNote, "apiKey": apiKey,
					}, nil
				},
			},
			"products": &graphql.Field{
				Type: graphql.NewList(productType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					rows, _ := db.Query("SELECT id, name, description, price, stock, category, internal_notes, supplier_cost FROM products")
					defer rows.Close()
					var products []map[string]interface{}
					for rows.Next() {
						var id, stock int
						var name string
						var desc, category, notes *string
						var price float64
						var cost *float64
						rows.Scan(&id, &name, &desc, &price, &stock, &category, &notes, &cost)
						products = append(products, map[string]interface{}{
							"id": id, "name": name, "description": desc, "price": price,
							"stock": stock, "category": category, "internalNotes": notes, "supplierCost": cost,
						})
					}
					return products, nil
				},
			},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"login": &graphql.Field{
				Type: authPayloadType,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					username := p.Args["username"].(string)
					password := p.Args["password"].(string)
					var user User
					var hash string
					err := db.QueryRow("SELECT id, username, role, password_hash FROM users WHERE username = ?", username).
						Scan(&user.ID, &user.Username, &user.Role, &hash)
					if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
						return nil, fmt.Errorf("invalid credentials")
					}
					token, _ := createToken(&user)
					return map[string]interface{}{
						"accessToken": token, "tokenType": "bearer", "userId": user.ID, "role": user.Role,
					}, nil
				},
			},
			"updateUser": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"id":   &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Int)},
					"role": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id := p.Args["id"].(int)
					if role, ok := p.Args["role"].(string); ok {
						db.Exec("UPDATE users SET role = ? WHERE id = ?", role, id)
					}
					var username, email, role string
					db.QueryRow("SELECT username, email, role FROM users WHERE id = ?", id).Scan(&username, &email, &role)
					return map[string]interface{}{"id": id, "username": username, "email": email, "role": role}, nil
				},
			},
		},
	})

	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})

	h := handler.New(&handler.Config{
		Schema:   &schema,
		Pretty:   true,
		GraphiQL: true, // VULNERABILITY G01
	})

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
