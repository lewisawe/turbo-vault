package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Agent represents a registered agent
type Agent struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	Version      string    `json:"version"`
	Capabilities []string  `json:"capabilities"`
}

// ControlPlaneService manages agents and policies
type ControlPlaneService struct {
	agents map[string]*Agent
}

func NewControlPlaneService() *ControlPlaneService {
	return &ControlPlaneService{
		agents: make(map[string]*Agent),
	}
}

func (cp *ControlPlaneService) RegisterAgent(c *gin.Context) {
	var agent Agent
	if err := c.ShouldBindJSON(&agent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent.Status = "active"
	agent.LastSeen = time.Now()
	cp.agents[agent.ID] = &agent

	log.Printf("Agent registered: %s", agent.ID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Agent registered successfully",
		"agent":   agent,
	})
}

func (cp *ControlPlaneService) ListAgents(c *gin.Context) {
	agents := make([]*Agent, 0, len(cp.agents))
	for _, agent := range cp.agents {
		agents = append(agents, agent)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    agents,
		"count":   len(agents),
	})
}

func (cp *ControlPlaneService) GetAgentStatus(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := cp.agents[agentID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    agent,
	})
}

func (cp *ControlPlaneService) GetDashboard(c *gin.Context) {
	activeAgents := 0
	for _, agent := range cp.agents {
		if agent.Status == "active" {
			activeAgents++
		}
	}

	dashboard := map[string]interface{}{
		"total_agents":  len(cp.agents),
		"active_agents": activeAgents,
		"system_status": "healthy",
		"uptime":        "2h 30m",
		"last_updated":  time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    dashboard,
	})
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	cp := NewControlPlaneService()

	// Add some demo agents
	cp.agents["demo-agent-001"] = &Agent{
		ID:           "demo-agent-001",
		Name:         "Vault Agent 1",
		Status:       "active",
		LastSeen:     time.Now().Add(-5 * time.Minute),
		Version:      "1.0.0",
		Capabilities: []string{"secrets", "encryption", "monitoring"},
	}

	// API routes
	api := router.Group("/api/v1")
	{
		api.POST("/agents/register", cp.RegisterAgent)
		api.GET("/agents", cp.ListAgents)
		api.GET("/agents/:id", cp.GetAgentStatus)
		api.GET("/dashboard", cp.GetDashboard)
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"service":   "control-plane",
		})
	})

	log.Println("Starting Control Plane Service on :8081")
	log.Fatal(http.ListenAndServe(":8081", router))
}
