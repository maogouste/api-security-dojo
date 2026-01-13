package handlers

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// PingHandler executes ping command - VULNERABILITY V07: Command injection
func PingHandler(c *gin.Context) {
	var req struct {
		Host string `json:"host"`
	}
	c.BindJSON(&req)

	// VULNERABILITY V07: Command injection
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", req.Host))
	output, err := cmd.CombinedOutput()

	c.JSON(200, gin.H{
		"success": err == nil,
		"command": fmt.Sprintf("ping -c 1 %s", req.Host),
		"output":  string(output),
	})
}

// DNSHandler executes nslookup - VULNERABILITY V07: Command injection
func DNSHandler(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	c.BindJSON(&req)

	// VULNERABILITY V07: Command injection
	cmd := exec.Command("sh", "-c", fmt.Sprintf("nslookup %s", req.Domain))
	output, _ := cmd.CombinedOutput()

	c.JSON(200, gin.H{"domain": req.Domain, "output": string(output)})
}

// DebugHandler exposes debug info - VULNERABILITY V08
func DebugHandler(c *gin.Context) {
	// VULNERABILITY V08: Exposes sensitive debug info
	c.JSON(200, gin.H{
		"go_version": "go1.21",
		"env_vars":   os.Environ(),
		"cwd":        func() string { d, _ := os.Getwd(); return d }(),
	})
}
