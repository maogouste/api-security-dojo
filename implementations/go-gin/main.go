// API Security Dojo - Go/Gin Implementation
//
// Deliberately vulnerable API for security learning.
// WARNING: This API contains intentional security vulnerabilities.
// Do NOT deploy in production.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"vulnapi/database"
	gql "vulnapi/graphql"
	"vulnapi/handlers"
	"vulnapi/middleware"
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	database.InitDB()
	defer database.Close()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// VULNERABILITY V08: CORS misconfiguration
	r.Use(middleware.CORSMiddleware())

	// Root
	r.GET("/", handlers.RootHandler)
	r.GET("/health", handlers.HealthHandler)

	// Auth routes
	r.POST("/api/register", handlers.RegisterHandler)
	r.POST("/api/login", handlers.LoginHandler)
	r.GET("/api/me", middleware.AuthMiddleware(), handlers.MeHandler)

	// Users routes
	r.GET("/api/users", middleware.OptionalAuth(), handlers.ListUsersHandler)
	r.GET("/api/users/:id", middleware.OptionalAuth(), handlers.GetUserHandler)
	r.PUT("/api/users/:id", middleware.AuthMiddleware(), handlers.UpdateUserHandler)
	r.DELETE("/api/users/:id", middleware.AuthMiddleware(), handlers.DeleteUserHandler)

	// Legacy API V1 - VULNERABILITY V09
	r.GET("/api/v1/users", handlers.ListUsersV1Handler)
	r.GET("/api/v1/users/:id", handlers.GetUserV1Handler)

	// Products routes
	r.GET("/api/products", handlers.ListProductsHandler)
	r.GET("/api/products/:id", handlers.GetProductHandler)

	// Tools routes
	r.POST("/api/tools/ping", middleware.AuthMiddleware(), handlers.PingHandler)
	r.POST("/api/tools/dns", middleware.AuthMiddleware(), handlers.DNSHandler)
	r.GET("/api/tools/debug", handlers.DebugHandler)

	// Flags routes
	r.GET("/api/challenges", handlers.ListChallengesHandler)
	r.POST("/api/flags/submit", middleware.AuthMiddleware(), handlers.SubmitFlagHandler)

	// Docs routes
	r.GET("/api/docs/mode", handlers.DocsModeHandler)
	r.GET("/api/docs/stats", handlers.DocsStatsHandler)
	r.GET("/api/docs/categories", handlers.DocsCategoriesHandler)
	r.GET("/api/docs/vulnerabilities", handlers.DocsVulnerabilitiesHandler)
	r.GET("/api/docs/vulnerabilities/:id", handlers.DocsVulnerabilityHandler)

	// GraphQL
	r.Any("/graphql", gql.GraphQLHandler())
	r.Any("/graphql/", gql.GraphQLHandler())

	port := getEnv("PORT", "3002")
	mode := handlers.Mode
	fmt.Printf(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   API Security Dojo - Go/Gin Implementation                         ║
║   ⚠️  WARNING: Intentionally Vulnerable API               ║
║                                                           ║
║   Mode: %-49s║
║   Server running on http://localhost:%-20s║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`, mode, port)

	log.Fatal(r.Run(":" + port))
}
