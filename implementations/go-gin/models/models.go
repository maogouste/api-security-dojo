// Package models defines the data structures for API Security Dojo
package models

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

// Order model
type Order struct {
	ID              int      `json:"id"`
	UserID          int      `json:"user_id"`
	Status          string   `json:"status"`
	TotalAmount     float64  `json:"total_amount"`
	ShippingAddress *string  `json:"shipping_address"`
	Notes           *string  `json:"notes"`
	CreatedAt       string   `json:"created_at"`
}
