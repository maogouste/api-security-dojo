package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// DocsModeHandler returns current mode
func DocsModeHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"mode":                  Mode,
		"documentation_enabled": Mode == "documentation",
		"description": func() string {
			if Mode == "documentation" {
				return "Documentation mode: Full exploitation details and remediation"
			}
			return "Challenge mode: Limited information, find vulnerabilities yourself"
		}(),
	})
}

// DocsStatsHandler returns vulnerability stats
func DocsStatsHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	stats := gin.H{
		"total":       len(vulns),
		"by_severity": map[string]int{},
		"by_category": map[string]int{},
		"rest_api":    0,
		"graphql":     0,
	}

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		stats["by_severity"].(map[string]int)[vm["severity"].(string)]++
		stats["by_category"].(map[string]int)[vm["category"].(string)]++
		if strings.HasPrefix(vm["id"].(string), "V") {
			stats["rest_api"] = stats["rest_api"].(int) + 1
		} else {
			stats["graphql"] = stats["graphql"].(int) + 1
		}
	}
	c.JSON(200, stats)
}

// DocsCategoriesHandler returns categories with vulnerabilities
func DocsCategoriesHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	categories := map[string]gin.H{}

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		cat := vm["category"].(string)
		if _, ok := categories[cat]; !ok {
			categories[cat] = gin.H{"name": cat, "count": 0, "vulnerabilities": []string{}}
		}
		categories[cat]["count"] = categories[cat]["count"].(int) + 1
		categories[cat]["vulnerabilities"] = append(categories[cat]["vulnerabilities"].([]string), vm["id"].(string))
	}

	var result []gin.H
	for _, v := range categories {
		result = append(result, v)
	}
	c.JSON(200, result)
}

// DocsVulnerabilitiesHandler returns filtered vulnerabilities
func DocsVulnerabilitiesHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	category := c.Query("category")
	severity := c.Query("severity")

	var result []gin.H
	for _, v := range vulns {
		vm := v.(map[string]interface{})
		if category != "" && vm["category"].(string) != category {
			continue
		}
		if severity != "" && vm["severity"].(string) != severity {
			continue
		}
		result = append(result, gin.H{
			"id":          vm["id"],
			"name":        vm["name"],
			"category":    vm["category"],
			"severity":    vm["severity"],
			"owasp":       vm["owasp"],
			"cwe":         vm["cwe"],
			"description": vm["description"],
		})
	}
	c.JSON(200, result)
}

// DocsVulnerabilityHandler returns a specific vulnerability
func DocsVulnerabilityHandler(c *gin.Context) {
	if Mode != "documentation" {
		c.JSON(403, gin.H{
			"error":        "Documentation mode is disabled",
			"message":      "Set DOJO_MODE=documentation to access vulnerability details",
			"current_mode": Mode,
		})
		return
	}

	id := c.Param("id")
	vulns := loadVulnerabilities()

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		if vm["id"].(string) == id {
			c.JSON(200, vm)
			return
		}
	}
	c.JSON(404, gin.H{"detail": fmt.Sprintf("Vulnerability %s not found", id)})
}

// Key differences for each vulnerability (educational summaries)
var keyDifferences = map[string]string{
	"V01": "Add authorization check: verify user owns the resource or has admin role",
	"V02": "Use strong secrets from environment + generic error messages",
	"V03": "Use response models (DTOs) to filter sensitive fields",
	"V04": "Implement rate limiting with sliding window or token bucket",
	"V05": "Whitelist allowed fields, never bind request directly to model",
	"V06": "Use parameterized queries, never concatenate user input into SQL",
	"V07": "Validate input strictly, use safe APIs instead of shell execution",
	"V08": "Configure CORS properly, disable debug endpoints in production",
	"V09": "Deprecate and remove old API versions, apply same security controls",
	"V10": "Log security events, implement alerting on suspicious patterns",
	"G01": "Disable introspection in production",
	"G02": "Set query depth limit: max_depth=10",
	"G03": "Limit batch size and implement query cost analysis",
	"G04": "Disable field suggestions in production errors",
	"G05": "Add authorization checks to all resolvers",
}

// DocsCompareListHandler lists all code comparisons
func DocsCompareListHandler(c *gin.Context) {
	vulns := loadVulnerabilities()
	var result []gin.H

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		id := vm["id"].(string)
		result = append(result, gin.H{
			"id":             id,
			"name":           vm["name"],
			"key_difference": keyDifferences[id],
		})
	}
	c.JSON(200, result)
}

// DocsCompareHandler compares vulnerable vs secure code
func DocsCompareHandler(c *gin.Context) {
	id := c.Param("id")
	vulns := loadVulnerabilities()

	for _, v := range vulns {
		vm := v.(map[string]interface{})
		if vm["id"].(string) == id {
			keyDiff := keyDifferences[id]
			if keyDiff == "" {
				keyDiff = "See secure_code for the fix"
			}
			c.JSON(200, gin.H{
				"id":              id,
				"name":            vm["name"],
				"vulnerable_code": vm["vulnerable_code"],
				"secure_code":     vm["secure_code"],
				"key_difference":  keyDiff,
				"remediation":     vm["remediation"],
				"owasp":           vm["owasp"],
				"cwe":             vm["cwe"],
			})
			return
		}
	}
	c.JSON(404, gin.H{"detail": fmt.Sprintf("Vulnerability %s not found", id)})
}

func loadVulnerabilities() []interface{} {
	data, err := os.ReadFile("vulnerabilities.json")
	if err != nil {
		return []interface{}{}
	}
	var doc map[string]interface{}
	json.Unmarshal(data, &doc)
	if vulns, ok := doc["vulnerabilities"].([]interface{}); ok {
		return vulns
	}
	return []interface{}{}
}
