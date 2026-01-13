package handlers

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"vulnapi/database"
	"vulnapi/models"
)

// ListUsersHandler returns all users
func ListUsersHandler(c *gin.Context) {
	rows, _ := database.DB.Query("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users")
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.IsActive, &u.SSN, &u.CreditCard, &u.SecretNote, &u.APIKey, &u.CreatedAt)
		users = append(users, u)
	}
	c.JSON(200, users)
}

// GetUserHandler returns a single user
func GetUserHandler(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	// VULNERABILITY V01: No authorization check
	err := database.DB.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey, &user.CreatedAt)
	if err != nil {
		c.JSON(404, gin.H{"detail": "User not found"})
		return
	}
	c.JSON(200, user)
}

// UpdateUserHandler updates a user
func UpdateUserHandler(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	c.BindJSON(&updates)

	// VULNERABILITY V05: Mass assignment
	for field, value := range updates {
		if field == "password" {
			hash, _ := bcrypt.GenerateFromPassword([]byte(value.(string)), 4)
			database.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
		} else {
			database.DB.Exec(fmt.Sprintf("UPDATE users SET %s = ? WHERE id = ?", field), value, id)
		}
	}

	var user models.User
	database.DB.QueryRow("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey)
	c.JSON(200, user)
}

// DeleteUserHandler deletes a user
func DeleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	c.JSON(200, gin.H{"message": "User deleted"})
}

// Legacy API handlers - VULNERABILITY V09

// ListUsersV1Handler returns all users with password hashes (legacy)
func ListUsersV1Handler(c *gin.Context) {
	rows, _ := database.DB.Query("SELECT id, username, email, password_hash, role, ssn, credit_card, secret_note, api_key FROM users")
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.SSN, &u.CreditCard, &u.SecretNote, &u.APIKey)
		users = append(users, u)
	}
	c.JSON(200, users)
}

// GetUserV1Handler returns a single user with password hash (legacy)
func GetUserV1Handler(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	database.DB.QueryRow("SELECT id, username, email, password_hash, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.SSN, &user.CreditCard, &user.SecretNote, &user.APIKey)
	c.JSON(200, user)
}
