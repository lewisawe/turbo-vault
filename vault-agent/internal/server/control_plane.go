package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type ControlPlaneClient struct {
	baseURL  string
	agentID  string
	client   *http.Client
	stopChan chan bool
}

type AgentInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

func NewControlPlaneClient(baseURL, agentID string) *ControlPlaneClient {
	return &ControlPlaneClient{
		baseURL:  baseURL,
		agentID:  agentID,
		client:   &http.Client{Timeout: 10 * time.Second},
		stopChan: make(chan bool),
	}
}

func (cp *ControlPlaneClient) Register() error {
	agent := AgentInfo{
		ID:           cp.agentID,
		Name:         "Vault Agent",
		Version:      "1.0.0",
		Capabilities: []string{"secrets", "encryption", "monitoring"},
	}

	jsonData, err := json.Marshal(agent)
	if err != nil {
		return fmt.Errorf("failed to marshal agent info: %w", err)
	}

	resp, err := cp.client.Post(
		cp.baseURL+"/api/v1/agents/register",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to register with control plane: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	log.Printf("Successfully registered with control plane as %s", cp.agentID)
	return nil
}

func (cp *ControlPlaneClient) StartHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				cp.sendHeartbeat()
			case <-cp.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (cp *ControlPlaneClient) sendHeartbeat() {
	resp, err := cp.client.Post(
		cp.baseURL+"/api/v1/agents/"+cp.agentID+"/heartbeat",
		"application/json",
		nil,
	)
	if err != nil {
		log.Printf("Failed to send heartbeat: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Heartbeat failed with status: %d", resp.StatusCode)
	}
}

func (cp *ControlPlaneClient) Stop() {
	close(cp.stopChan)
}
