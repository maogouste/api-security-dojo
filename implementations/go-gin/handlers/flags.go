package handlers

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"vulnapi/database"
	"vulnapi/models"
)

// ListChallengesHandler returns available challenges
func ListChallengesHandler(c *gin.Context) {
	rows, _ := database.DB.Query("SELECT challenge_id, description FROM flags")
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

// SubmitFlagHandler validates a submitted flag
func SubmitFlagHandler(c *gin.Context) {
	var req struct {
		Flag string `json:"flag"`
	}
	c.BindJSON(&req)

	var f models.Flag
	err := database.DB.QueryRow("SELECT challenge_id, description FROM flags WHERE flag_value = ?", req.Flag).Scan(&f.ChallengeID, &f.Description)
	if err != nil {
		c.JSON(200, gin.H{"success": false, "message": "Invalid flag"})
		return
	}
	c.JSON(200, gin.H{"success": true, "message": fmt.Sprintf("Congratulations! You solved challenge %s!", f.ChallengeID), "challenge_id": f.ChallengeID})
}
