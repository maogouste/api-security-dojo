// Package gql provides GraphQL handler with vulnerabilities G01-G05
package gql

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
	"golang.org/x/crypto/bcrypt"
	"vulnapi/database"
	"vulnapi/middleware"
	"vulnapi/models"
)

// GraphQLHandler returns a Gin handler for GraphQL requests
func GraphQLHandler() gin.HandlerFunc {
	// Forward declarations for circular references (G02)
	var userType, orderType *graphql.Object

	// Product type - VULNERABILITY G05: Exposes internal data without auth
	productType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Product",
		Fields: graphql.Fields{
			"id":            &graphql.Field{Type: graphql.Int},
			"name":          &graphql.Field{Type: graphql.String},
			"description":   &graphql.Field{Type: graphql.String},
			"price":         &graphql.Field{Type: graphql.Float},
			"stock":         &graphql.Field{Type: graphql.Int},
			"category":      &graphql.Field{Type: graphql.String},
			"internalNotes": &graphql.Field{Type: graphql.String}, // VULNERABILITY: Internal data
			"supplierCost":  &graphql.Field{Type: graphql.Float},  // VULNERABILITY: Internal data
		},
	})

	// Order type - VULNERABILITY G02: Enables nesting back to User (circular)
	orderType = graphql.NewObject(graphql.ObjectConfig{
		Name: "Order",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id":              &graphql.Field{Type: graphql.Int},
				"userId":          &graphql.Field{Type: graphql.Int},
				"status":          &graphql.Field{Type: graphql.String},
				"totalAmount":     &graphql.Field{Type: graphql.Float},
				"shippingAddress": &graphql.Field{Type: graphql.String},
				"notes":           &graphql.Field{Type: graphql.String},
				// VULNERABILITY G02: Circular reference enables deep nesting
				"user": &graphql.Field{
					Type:        userType,
					Description: "VULNERABILITY G02: Enables deep nesting (order->user->orders->user...)",
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						order := p.Source.(map[string]interface{})
						userId := order["userId"].(int)
						var username, email, role string
						var ssn, creditCard, secretNote, apiKey *string
						database.DB.QueryRow("SELECT username, email, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", userId).
							Scan(&username, &email, &role, &ssn, &creditCard, &secretNote, &apiKey)
						return map[string]interface{}{
							"id": userId, "username": username, "email": email, "role": role,
							"ssn": ssn, "creditCard": creditCard, "secretNote": secretNote, "apiKey": apiKey,
						}, nil
					},
				},
			}
		}),
	})

	// User type - VULNERABILITY G02, G05: Exposes sensitive fields and enables nesting
	userType = graphql.NewObject(graphql.ObjectConfig{
		Name: "User",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id":         &graphql.Field{Type: graphql.Int},
				"username":   &graphql.Field{Type: graphql.String},
				"email":      &graphql.Field{Type: graphql.String},
				"role":       &graphql.Field{Type: graphql.String},
				"ssn":        &graphql.Field{Type: graphql.String}, // VULNERABILITY G05: Sensitive
				"creditCard": &graphql.Field{Type: graphql.String}, // VULNERABILITY G05: Sensitive
				"secretNote": &graphql.Field{Type: graphql.String}, // VULNERABILITY G05: Sensitive
				"apiKey":     &graphql.Field{Type: graphql.String}, // VULNERABILITY G05: Sensitive
				// VULNERABILITY G02: Circular reference enables deep nesting
				"orders": &graphql.Field{
					Type:        graphql.NewList(orderType),
					Description: "VULNERABILITY G02: Enables deep nesting (user->orders->user->orders...)",
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						user := p.Source.(map[string]interface{})
						userId := user["id"].(int)
						rows, _ := database.DB.Query("SELECT id, user_id, status, total_amount, shipping_address, notes FROM orders WHERE user_id = ?", userId)
						if rows == nil {
							return []map[string]interface{}{}, nil
						}
						defer rows.Close()
						var orders []map[string]interface{}
						for rows.Next() {
							var id, uid int
							var status string
							var total float64
							var addr, notes *string
							rows.Scan(&id, &uid, &status, &total, &addr, &notes)
							orders = append(orders, map[string]interface{}{
								"id": id, "userId": uid, "status": status, "totalAmount": total,
								"shippingAddress": addr, "notes": notes,
							})
						}
						return orders, nil
					},
				},
			}
		}),
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

	// Query type - VULNERABILITY G05: No auth checks on sensitive queries
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			// VULNERABILITY G05: No authentication - exposes all users with sensitive data
			"users": &graphql.Field{
				Type:        graphql.NewList(userType),
				Description: "VULNERABILITY G05: No auth check - exposes all users with sensitive data",
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					rows, _ := database.DB.Query("SELECT id, username, email, role, ssn, credit_card, secret_note, api_key FROM users")
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
			// VULNERABILITY G05: No authorization check - any user can access any user's data
			"user": &graphql.Field{
				Type:        userType,
				Description: "VULNERABILITY G05: No authorization check",
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Int)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id := p.Args["id"].(int)
					var username, email, role string
					var ssn, creditCard, secretNote, apiKey *string
					database.DB.QueryRow("SELECT username, email, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
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
					rows, _ := database.DB.Query("SELECT id, name, description, price, stock, category, internal_notes, supplier_cost FROM products")
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
			// VULNERABILITY G05: No auth - exposes all orders
			"orders": &graphql.Field{
				Type:        graphql.NewList(orderType),
				Description: "VULNERABILITY G05: No authentication - exposes all orders",
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					rows, _ := database.DB.Query("SELECT id, user_id, status, total_amount, shipping_address, notes FROM orders")
					if rows == nil {
						return []map[string]interface{}{}, nil
					}
					defer rows.Close()
					var orders []map[string]interface{}
					for rows.Next() {
						var id, uid int
						var status string
						var total float64
						var addr, notes *string
						rows.Scan(&id, &uid, &status, &total, &addr, &notes)
						orders = append(orders, map[string]interface{}{
							"id": id, "userId": uid, "status": status, "totalAmount": total,
							"shippingAddress": addr, "notes": notes,
						})
					}
					return orders, nil
				},
			},
		},
	})

	// Mutation type - VULNERABILITY G05: No proper auth checks
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
					var user models.User
					var hash string
					err := database.DB.QueryRow("SELECT id, username, role, password_hash FROM users WHERE username = ?", username).
						Scan(&user.ID, &user.Username, &user.Role, &hash)
					if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
						return nil, fmt.Errorf("invalid credentials")
					}
					token, _ := middleware.CreateToken(&user)
					return map[string]interface{}{
						"accessToken": token, "tokenType": "bearer", "userId": user.ID, "role": user.Role,
					}, nil
				},
			},
			// VULNERABILITY G05: No authorization - anyone can update anyone
			"updateUser": &graphql.Field{
				Type:        userType,
				Description: "VULNERABILITY G05: No authorization check - anyone can update anyone",
				Args: graphql.FieldConfigArgument{
					"id":       &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Int)},
					"username": &graphql.ArgumentConfig{Type: graphql.String},
					"email":    &graphql.ArgumentConfig{Type: graphql.String},
					"role":     &graphql.ArgumentConfig{Type: graphql.String}, // VULNERABILITY: Can escalate privileges
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id := p.Args["id"].(int)
					if role, ok := p.Args["role"].(string); ok {
						database.DB.Exec("UPDATE users SET role = ? WHERE id = ?", role, id)
					}
					if username, ok := p.Args["username"].(string); ok {
						database.DB.Exec("UPDATE users SET username = ? WHERE id = ?", username, id)
					}
					if email, ok := p.Args["email"].(string); ok {
						database.DB.Exec("UPDATE users SET email = ? WHERE id = ?", email, id)
					}
					var username, email, role string
					var ssn, creditCard, secretNote, apiKey *string
					database.DB.QueryRow("SELECT username, email, role, ssn, credit_card, secret_note, api_key FROM users WHERE id = ?", id).
						Scan(&username, &email, &role, &ssn, &creditCard, &secretNote, &apiKey)
					return map[string]interface{}{
						"id": id, "username": username, "email": email, "role": role,
						"ssn": ssn, "creditCard": creditCard, "secretNote": secretNote, "apiKey": apiKey,
					}, nil
				},
			},
		},
	})

	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})

	// Custom handler for G03 (batching) and G04 (field suggestions)
	return func(c *gin.Context) {
		if c.Request.Method == "GET" {
			// Serve GraphiQL UI - VULNERABILITY G01
			h := handler.New(&handler.Config{
				Schema:   &schema,
				Pretty:   true,
				GraphiQL: true,
			})
			h.ServeHTTP(c.Writer, c.Request)
			return
		}

		// POST - Handle batching (G03)
		var body interface{}
		if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
			c.JSON(400, gin.H{"errors": []gin.H{{"message": "Invalid JSON"}}})
			return
		}

		// VULNERABILITY G03: Process batched queries without any limits
		if queries, ok := body.([]interface{}); ok {
			// Batched query - process each one without limits
			var results []map[string]interface{}
			for _, q := range queries {
				qMap := q.(map[string]interface{})
				query := qMap["query"].(string)
				var variables map[string]interface{}
				if v, ok := qMap["variables"].(map[string]interface{}); ok {
					variables = v
				}
				result := graphql.Do(graphql.Params{
					Schema:         schema,
					RequestString:  query,
					VariableValues: variables,
				})
				respData := map[string]interface{}{"data": result.Data}
				if len(result.Errors) > 0 {
					// VULNERABILITY G04: Include field suggestions in errors
					var errs []map[string]interface{}
					for _, e := range result.Errors {
						errs = append(errs, map[string]interface{}{
							"message":   e.Message,
							"locations": e.Locations,
							"path":      e.Path,
						})
					}
					respData["errors"] = errs
				}
				results = append(results, respData)
			}
			c.JSON(200, results)
			return
		}

		// Single query
		qMap := body.(map[string]interface{})
		query := qMap["query"].(string)
		var variables map[string]interface{}
		if v, ok := qMap["variables"].(map[string]interface{}); ok {
			variables = v
		}
		var operationName string
		if op, ok := qMap["operationName"].(string); ok {
			operationName = op
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  query,
			VariableValues: variables,
			OperationName:  operationName,
		})

		respData := map[string]interface{}{"data": result.Data}
		if len(result.Errors) > 0 {
			// VULNERABILITY G04: Include detailed error messages with field suggestions
			var errs []map[string]interface{}
			for _, e := range result.Errors {
				errs = append(errs, map[string]interface{}{
					"message":   e.Message,
					"locations": e.Locations,
					"path":      e.Path,
				})
			}
			respData["errors"] = errs
		}
		c.JSON(200, respData)
	}
}
