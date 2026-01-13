package handlers

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"vulnapi/database"
	"vulnapi/models"
)

// ListProductsHandler returns products with SQL injection vulnerability
func ListProductsHandler(c *gin.Context) {
	search := c.Query("search")
	var rows *sql.Rows

	if search != "" {
		// VULNERABILITY V06: SQL Injection
		query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%' OR description LIKE '%%%s%%'", search, search)
		rows, _ = database.DB.Query(query)
	} else {
		rows, _ = database.DB.Query("SELECT * FROM products WHERE is_active = 1")
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.Category, &p.IsActive, &p.InternalNotes, &p.SupplierCost, &p.CreatedAt)
		products = append(products, p)
	}
	c.JSON(200, products)
}

// GetProductHandler returns a single product
func GetProductHandler(c *gin.Context) {
	id := c.Param("id")
	var p models.Product
	database.DB.QueryRow("SELECT * FROM products WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.Category, &p.IsActive, &p.InternalNotes, &p.SupplierCost, &p.CreatedAt)
	c.JSON(200, p)
}
