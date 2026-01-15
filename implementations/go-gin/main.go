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

// checkProductionEnvironment checks if running in a production-like environment
// and blocks startup unless DOJO_FORCE_START=true is set.
func checkProductionEnvironment() {
	indicators := map[string]string{
		"PRODUCTION":               os.Getenv("PRODUCTION"),
		"PROD":                     os.Getenv("PROD"),
		"AWS_EXECUTION_ENV":        os.Getenv("AWS_EXECUTION_ENV"),
		"AWS_LAMBDA_FUNCTION_NAME": os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
		"KUBERNETES_SERVICE_HOST":  os.Getenv("KUBERNETES_SERVICE_HOST"),
		"ECS_CONTAINER_METADATA_URI": os.Getenv("ECS_CONTAINER_METADATA_URI"),
		"GOOGLE_CLOUD_PROJECT":     os.Getenv("GOOGLE_CLOUD_PROJECT"),
		"HEROKU_APP_NAME":          os.Getenv("HEROKU_APP_NAME"),
		"VERCEL":                   os.Getenv("VERCEL"),
		"RENDER":                   os.Getenv("RENDER"),
	}

	// Check NODE_ENV and ENVIRONMENT separately
	if os.Getenv("NODE_ENV") == "production" {
		indicators["NODE_ENV=production"] = "true"
	}
	if os.Getenv("ENVIRONMENT") == "production" {
		indicators["ENVIRONMENT=production"] = "true"
	}

	var detected []string
	for k, v := range indicators {
		if v != "" {
			detected = append(detected, fmt.Sprintf("    - %s: %s", k, v))
		}
	}

	if len(detected) > 0 {
		fmt.Fprintln(os.Stderr, `
================================================================================
                    CRITICAL SECURITY WARNING
================================================================================

  API Security Dojo has detected a PRODUCTION-LIKE environment!

  Detected indicators:`)
		for _, d := range detected {
			fmt.Fprintln(os.Stderr, d)
		}
		fmt.Fprintln(os.Stderr, `
  THIS APPLICATION IS INTENTIONALLY VULNERABLE!
  It contains security vulnerabilities by design for educational purposes.

  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!

================================================================================`)

		if os.Getenv("DOJO_FORCE_START") != "true" {
			fmt.Fprintln(os.Stderr, "  To override this safety check (NOT RECOMMENDED), set:")
			fmt.Fprintln(os.Stderr, "    DOJO_FORCE_START=true")
			os.Exit(1)
		} else {
			fmt.Fprintln(os.Stderr, "  WARNING: DOJO_FORCE_START=true detected.")
			fmt.Fprintln(os.Stderr, "  Proceeding despite production environment detection.")
			fmt.Fprintln(os.Stderr, "  YOU HAVE BEEN WARNED!")
		}
	}
}

func main() {
	// Check production environment before proceeding
	checkProductionEnvironment()
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
	r.GET("/api/docs/compare", handlers.DocsCompareListHandler)
	r.GET("/api/docs/compare/:id", handlers.DocsCompareHandler)

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
