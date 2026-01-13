// Package middleware provides HTTP middleware for API Security Dojo
package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"vulnapi/database"
	"vulnapi/models"
)

// VULNERABILITY V02: Weak secret key
var JwtSecret = []byte("secret123")

// CreateToken generates a JWT token for a user
func CreateToken(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":     user.Username,
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString(JwtSecret)
}

// ParseToken validates and parses a JWT token
func ParseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// AuthMiddleware requires a valid JWT token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(401, gin.H{"detail": "Not authenticated"})
			c.Abort()
			return
		}
		claims, err := ParseToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			c.JSON(401, gin.H{"detail": "Invalid token"})
			c.Abort()
			return
		}
		userID := int(claims["user_id"].(float64))
		var user models.User
		err = database.DB.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", userID).
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

// OptionalAuth optionally authenticates if a token is provided
func OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			if claims, err := ParseToken(strings.TrimPrefix(auth, "Bearer ")); err == nil {
				userID := int(claims["user_id"].(float64))
				var user models.User
				if err := database.DB.QueryRow("SELECT id, username, email, role FROM users WHERE id = ?", userID).
					Scan(&user.ID, &user.Username, &user.Email, &user.Role); err == nil {
					c.Set("user", &user)
				}
			}
		}
		c.Next()
	}
}

// CORSMiddleware adds CORS headers - VULNERABILITY V08: Overly permissive
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
