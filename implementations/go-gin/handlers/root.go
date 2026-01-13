// Package handlers provides HTTP handlers for API Security Dojo
package handlers

import (
	"os"

	"github.com/gin-gonic/gin"
)

var Mode = getEnv("DOJO_MODE", "challenge")

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// RootHandler returns API info
func RootHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"name":           "API Security Dojo",
		"version":        "0.2.0",
		"mode":           Mode,
		"implementation": "Go/Gin",
		"message":        "Welcome to API Security Dojo - A deliberately vulnerable API",
	})
}

// HealthHandler returns health status
func HealthHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "healthy", "implementation": "go-gin"})
}
