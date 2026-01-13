package handlers

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"vulnapi/database"
	"vulnapi/middleware"
	"vulnapi/models"
)

// RegisterHandler handles user registration
func RegisterHandler(c *gin.Context) {
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
	result, err := database.DB.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')`,
		req.Username, req.Email, string(hash))
	if err != nil {
		c.JSON(400, gin.H{"detail": "Username or email already exists"})
		return
	}
	id, _ := result.LastInsertId()
	c.JSON(201, gin.H{"id": id, "username": req.Username, "email": req.Email, "role": "user"})
}

// LoginHandler handles user login
func LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "Invalid request"})
		return
	}
	var user models.User
	var hash string
	err := database.DB.QueryRow("SELECT id, username, email, password_hash, role FROM users WHERE username = ?", req.Username).
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
	token, _ := middleware.CreateToken(&user)
	c.JSON(200, gin.H{"access_token": token, "token_type": "bearer", "user_id": user.ID, "role": user.Role})
}

// MeHandler returns current user info
func MeHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	c.JSON(200, user)
}
