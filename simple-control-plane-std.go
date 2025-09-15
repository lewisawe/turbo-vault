package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
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
	cp := &ControlPlaneService{
		agents: make(map[string]*Agent),
	}
	
	// Add demo agent
	cp.agents["demo-agent-001"] = &Agent{
		ID:           "demo-agent-001",
		Name:         "Vault Agent 1",
		Status:       "active",
		LastSeen:     time.Now().Add(-5 * time.Minute),
		Version:      "1.0.0",
		Capabilities: []string{"secrets", "encryption", "monitoring"},
	}
	
	return cp
}

func (cp *ControlPlaneService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"service":   "control-plane",
	}
	json.NewEncoder(w).Encode(response)
}

func (cp *ControlPlaneService) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	agents := make([]*Agent, 0, len(cp.agents))
	for _, agent := range cp.agents {
		agents = append(agents, agent)
	}

	response := map[string]interface{}{
		"success": true,
		"data":    agents,
		"count":   len(agents),
	}
	json.NewEncoder(w).Encode(response)
}

func (cp *ControlPlaneService) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
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

	response := map[string]interface{}{
		"success": true,
		"data":    dashboard,
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	cp := NewControlPlaneService()

	http.HandleFunc("/health", cp.handleHealth)
	http.HandleFunc("/api/v1/agents", cp.handleAgents)
	http.HandleFunc("/api/v1/dashboard", cp.handleDashboard)

	log.Println("Starting Control Plane Service on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
