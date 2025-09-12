package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ClusterManager manages high-availability and clustering functionality
type ClusterManager struct {
	storage     *Storage
	nodeID      string
	isLeader    bool
	leaderID    string
	mu          sync.RWMutex
	stopCh      chan struct{}
	healthCh    chan HealthStatus
	config      *ClusterConfig
	db          *sql.DB
}

// ClusterConfig contains clustering configuration
type ClusterConfig struct {
	NodeID              string        `yaml:"node_id" json:"node_id"`
	LeaderElectionTTL   time.Duration `yaml:"leader_election_ttl" json:"leader_election_ttl"`
	HeartbeatInterval   time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	FailoverTimeout     time.Duration `yaml:"failover_timeout" json:"failover_timeout"`
	SessionAffinity     bool          `yaml:"session_affinity" json:"session_affinity"`
	LoadBalancing       LoadBalancingConfig `yaml:"load_balancing" json:"load_balancing"`
}

// LoadBalancingConfig contains load balancing configuration
type LoadBalancingConfig struct {
	Strategy    string  `yaml:"strategy" json:"strategy"` // round_robin, least_connections, weighted
	HealthCheck bool    `yaml:"health_check" json:"health_check"`
	Weights     map[string]int `yaml:"weights" json:"weights"`
}

// NodeInfo represents information about a cluster node
type NodeInfo struct {
	ID           string            `json:"id" db:"id"`
	Address      string            `json:"address" db:"address"`
	Port         int               `json:"port" db:"port"`
	Status       NodeStatus        `json:"status" db:"status"`
	IsLeader     bool              `json:"is_leader" db:"is_leader"`
	LastSeen     time.Time         `json:"last_seen" db:"last_seen"`
	Version      string            `json:"version" db:"version"`
	Metadata     map[string]string `json:"metadata" db:"metadata"`
	LoadMetrics  LoadMetrics       `json:"load_metrics" db:"load_metrics"`
	RegisteredAt time.Time         `json:"registered_at" db:"registered_at"`
}

// NodeStatus represents the status of a cluster node
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusFailed   NodeStatus = "failed"
	NodeStatusLeaving  NodeStatus = "leaving"
)

// LoadMetrics contains node performance metrics
type LoadMetrics struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	ActiveSessions int     `json:"active_sessions"`
	RequestsPerSec float64 `json:"requests_per_sec"`
	ResponseTime   float64 `json:"response_time_ms"`
	ErrorRate      float64 `json:"error_rate"`
}

// HealthStatus represents the health status of a node
type HealthStatus struct {
	NodeID    string    `json:"node_id"`
	Healthy   bool      `json:"healthy"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
}

// LeaderElection manages leader election for background tasks
type LeaderElection struct {
	nodeID    string
	db        *sql.DB
	ttl       time.Duration
	isLeader  bool
	leaderID  string
	mu        sync.RWMutex
	stopCh    chan struct{}
}

// NewClusterManager creates a new cluster manager
func NewClusterManager(storage *Storage, config *ClusterConfig, db *sql.DB) (*ClusterManager, error) {
	if config.NodeID == "" {
		config.NodeID = generateNodeID()
	}

	cm := &ClusterManager{
		storage:  storage,
		nodeID:   config.NodeID,
		config:   config,
		db:       db,
		stopCh:   make(chan struct{}),
		healthCh: make(chan HealthStatus, 100),
	}

	// Initialize cluster tables
	if err := cm.initializeTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize cluster tables: %w", err)
	}

	return cm, nil
}

// Start starts the cluster manager
func (cm *ClusterManager) Start(ctx context.Context) error {
	// Register this node
	if err := cm.registerNode(ctx); err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	// Perform initial leader election
	cm.performLeaderElection(ctx)

	// Start leader election
	go cm.runLeaderElection(ctx)

	// Start health monitoring
	go cm.runHealthMonitoring(ctx)

	// Start heartbeat
	go cm.runHeartbeat(ctx)

	return nil
}

// Stop stops the cluster manager
func (cm *ClusterManager) Stop(ctx context.Context) error {
	close(cm.stopCh)

	// Deregister node
	return cm.deregisterNode(ctx)
}

// IsLeader returns whether this node is the current leader
func (cm *ClusterManager) IsLeader() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.isLeader
}

// GetLeaderID returns the current leader node ID
func (cm *ClusterManager) GetLeaderID() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.leaderID
}

// GetActiveNodes returns all active nodes in the cluster
func (cm *ClusterManager) GetActiveNodes(ctx context.Context) ([]*NodeInfo, error) {
	query := `
	SELECT id, address, port, status, is_leader, last_seen, version, metadata, load_metrics, registered_at
	FROM cluster_nodes 
	WHERE status = ? AND last_seen > ?
	ORDER BY registered_at
	`
	
	cutoff := time.Now().Add(-cm.config.FailoverTimeout)
	rows, err := cm.db.QueryContext(ctx, query, NodeStatusActive, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query active nodes: %w", err)
	}
	defer rows.Close()

	var nodes []*NodeInfo
	for rows.Next() {
		node := &NodeInfo{}
		var metadataJSON, loadMetricsJSON string

		err := rows.Scan(
			&node.ID, &node.Address, &node.Port, &node.Status,
			&node.IsLeader, &node.LastSeen, &node.Version,
			&metadataJSON, &loadMetricsJSON, &node.RegisteredAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metadataJSON), &node.Metadata)
		json.Unmarshal([]byte(loadMetricsJSON), &node.LoadMetrics)

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// SelectHealthyNode selects a healthy node for load balancing
func (cm *ClusterManager) SelectHealthyNode(ctx context.Context, sessionID string) (*NodeInfo, error) {
	nodes, err := cm.GetActiveNodes(ctx)
	if err != nil {
		return nil, err
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no active nodes available")
	}

	// Apply session affinity if enabled
	if cm.config.SessionAffinity && sessionID != "" {
		if node := cm.getAffinityNode(nodes, sessionID); node != nil {
			return node, nil
		}
	}

	// Apply load balancing strategy
	switch cm.config.LoadBalancing.Strategy {
	case "least_connections":
		return cm.selectLeastConnections(nodes), nil
	case "weighted":
		return cm.selectWeighted(nodes), nil
	default: // round_robin
		return cm.selectRoundRobin(nodes), nil
	}
}

// initializeTables creates the necessary cluster tables
func (cm *ClusterManager) initializeTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS cluster_nodes (
			id VARCHAR(255) PRIMARY KEY,
			address VARCHAR(255) NOT NULL,
			port INTEGER NOT NULL,
			status VARCHAR(20) DEFAULT 'active',
			is_leader BOOLEAN DEFAULT FALSE,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			version VARCHAR(50) DEFAULT '',
			metadata TEXT DEFAULT '{}',
			load_metrics TEXT DEFAULT '{}',
			registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_nodes_last_seen ON cluster_nodes(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_nodes_leader ON cluster_nodes(is_leader)`,
		
		`CREATE TABLE IF NOT EXISTS leader_election (
			id INTEGER PRIMARY KEY,
			leader_id VARCHAR(255) NOT NULL,
			elected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			term INTEGER DEFAULT 1
		)`,
		
		`CREATE TABLE IF NOT EXISTS cluster_sessions (
			session_id VARCHAR(255) PRIMARY KEY,
			node_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_sessions_node ON cluster_sessions(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_sessions_expires ON cluster_sessions(expires_at)`,
	}

	for _, query := range queries {
		if _, err := cm.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// registerNode registers this node in the cluster
func (cm *ClusterManager) registerNode(ctx context.Context) error {
	metadataJSON, _ := json.Marshal(map[string]string{
		"version": "1.0.0", // This should come from build info
		"role":    "vault-agent",
	})

	loadMetricsJSON, _ := json.Marshal(LoadMetrics{})

	query := `
	INSERT OR REPLACE INTO cluster_nodes 
	(id, address, port, status, is_leader, last_seen, version, metadata, load_metrics, registered_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := cm.db.ExecContext(ctx, query,
		cm.nodeID, "localhost", 8080, NodeStatusActive, false,
		time.Now(), "1.0.0", string(metadataJSON), string(loadMetricsJSON), time.Now())

	return err
}

// deregisterNode removes this node from the cluster
func (cm *ClusterManager) deregisterNode(ctx context.Context) error {
	query := `UPDATE cluster_nodes SET status = ?, last_seen = ? WHERE id = ?`
	_, err := cm.db.ExecContext(ctx, query, NodeStatusLeaving, time.Now(), cm.nodeID)
	return err
}

// runLeaderElection runs the leader election process
func (cm *ClusterManager) runLeaderElection(ctx context.Context) {
	ticker := time.NewTicker(cm.config.LeaderElectionTTL / 3)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.performLeaderElection(ctx)
		}
	}
}

// performLeaderElection attempts to become or maintain leadership
func (cm *ClusterManager) performLeaderElection(ctx context.Context) {
	tx, err := cm.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()

	// Check current leader
	var currentLeader string
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, 
		"SELECT leader_id, expires_at FROM leader_election ORDER BY term DESC LIMIT 1").
		Scan(&currentLeader, &expiresAt)

	now := time.Now()
	
	if err == sql.ErrNoRows || expiresAt.Before(now) {
		// No leader or leadership expired, try to become leader
		_, err = tx.ExecContext(ctx,
			"INSERT INTO leader_election (leader_id, expires_at, term) VALUES (?, ?, COALESCE((SELECT MAX(term) FROM leader_election), 0) + 1)",
			cm.nodeID, now.Add(cm.config.LeaderElectionTTL))
		
		if err == nil {
			cm.mu.Lock()
			cm.isLeader = true
			cm.leaderID = cm.nodeID
			cm.mu.Unlock()

			// Update node status
			tx.ExecContext(ctx, "UPDATE cluster_nodes SET is_leader = TRUE WHERE id = ?", cm.nodeID)
			tx.Commit()
			return
		}
	}

	if currentLeader == cm.nodeID {
		// Extend leadership
		_, err = tx.ExecContext(ctx,
			"UPDATE leader_election SET expires_at = ? WHERE leader_id = ?",
			now.Add(cm.config.LeaderElectionTTL), cm.nodeID)
		
		if err == nil {
			cm.mu.Lock()
			cm.isLeader = true
			cm.leaderID = cm.nodeID
			cm.mu.Unlock()
			tx.Commit()
			return
		}
	}

	// Not leader
	cm.mu.Lock()
	cm.isLeader = false
	cm.leaderID = currentLeader
	cm.mu.Unlock()

	// Update node status
	tx.ExecContext(ctx, "UPDATE cluster_nodes SET is_leader = FALSE WHERE id = ?", cm.nodeID)
	tx.Commit()
}

// runHealthMonitoring monitors cluster health
func (cm *ClusterManager) runHealthMonitoring(ctx context.Context) {
	ticker := time.NewTicker(cm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.performHealthCheck(ctx)
		case health := <-cm.healthCh:
			cm.processHealthStatus(ctx, health)
		}
	}
}

// performHealthCheck checks the health of all nodes
func (cm *ClusterManager) performHealthCheck(ctx context.Context) {
	// Check database connectivity
	healthy := true
	details := ""

	if err := cm.storage.HealthCheck(ctx); err != nil {
		healthy = false
		details = fmt.Sprintf("storage health check failed: %v", err)
	}

	// Send health status
	select {
	case cm.healthCh <- HealthStatus{
		NodeID:    cm.nodeID,
		Healthy:   healthy,
		Timestamp: time.Now(),
		Details:   details,
	}:
	default:
		// Channel full, skip
	}

	// Mark inactive nodes as failed
	cutoff := time.Now().Add(-cm.config.FailoverTimeout)
	_, err := cm.db.ExecContext(ctx,
		"UPDATE cluster_nodes SET status = ? WHERE last_seen < ? AND status = ?",
		NodeStatusFailed, cutoff, NodeStatusActive)
	if err != nil {
		// Log error but continue
	}
}

// processHealthStatus processes a health status update
func (cm *ClusterManager) processHealthStatus(ctx context.Context, health HealthStatus) {
	status := NodeStatusActive
	if !health.Healthy {
		status = NodeStatusFailed
	}

	_, err := cm.db.ExecContext(ctx,
		"UPDATE cluster_nodes SET status = ?, last_seen = ? WHERE id = ?",
		status, health.Timestamp, health.NodeID)
	if err != nil {
		// Log error but continue
	}
}

// runHeartbeat sends periodic heartbeats
func (cm *ClusterManager) runHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(cm.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat sends a heartbeat for this node
func (cm *ClusterManager) sendHeartbeat(ctx context.Context) {
	// Update load metrics
	loadMetrics := LoadMetrics{
		CPUUsage:       getCPUUsage(),
		MemoryUsage:    getMemoryUsage(),
		ActiveSessions: getActiveSessions(),
		RequestsPerSec: getRequestsPerSec(),
		ResponseTime:   getResponseTime(),
		ErrorRate:      getErrorRate(),
	}

	loadMetricsJSON, _ := json.Marshal(loadMetrics)

	_, err := cm.db.ExecContext(ctx,
		"UPDATE cluster_nodes SET last_seen = ?, load_metrics = ? WHERE id = ?",
		time.Now(), string(loadMetricsJSON), cm.nodeID)
	if err != nil {
		// Log error but continue
	}
}

// Load balancing helper methods

func (cm *ClusterManager) getAffinityNode(nodes []*NodeInfo, sessionID string) *NodeInfo {
	// Check if session exists and node is still active
	var nodeID string
	err := cm.db.QueryRow(
		"SELECT node_id FROM cluster_sessions WHERE session_id = ? AND expires_at > ?",
		sessionID, time.Now()).Scan(&nodeID)
	
	if err != nil {
		return nil
	}

	for _, node := range nodes {
		if node.ID == nodeID {
			return node
		}
	}

	return nil
}

func (cm *ClusterManager) selectLeastConnections(nodes []*NodeInfo) *NodeInfo {
	if len(nodes) == 0 {
		return nil
	}

	minConnections := nodes[0].LoadMetrics.ActiveSessions
	selected := nodes[0]

	for _, node := range nodes[1:] {
		if node.LoadMetrics.ActiveSessions < minConnections {
			minConnections = node.LoadMetrics.ActiveSessions
			selected = node
		}
	}

	return selected
}

func (cm *ClusterManager) selectWeighted(nodes []*NodeInfo) *NodeInfo {
	if len(nodes) == 0 {
		return nil
	}

	// Simple weighted selection based on inverse load
	totalWeight := 0.0
	for _, node := range nodes {
		weight := 1.0 / (1.0 + node.LoadMetrics.CPUUsage + node.LoadMetrics.MemoryUsage)
		totalWeight += weight
	}

	// This is a simplified implementation
	// In production, you'd want a proper weighted random selection
	return nodes[0]
}

func (cm *ClusterManager) selectRoundRobin(nodes []*NodeInfo) *NodeInfo {
	if len(nodes) == 0 {
		return nil
	}

	// Simple round-robin based on node registration time
	// In production, you'd maintain a proper round-robin counter
	return nodes[0]
}

// Utility functions for metrics (these would be implemented properly)

func getCPUUsage() float64 {
	// Placeholder - would use actual system metrics
	return 0.5
}

func getMemoryUsage() float64 {
	// Placeholder - would use actual system metrics
	return 0.3
}

func getActiveSessions() int {
	// Placeholder - would track actual active sessions
	return 10
}

func getRequestsPerSec() float64 {
	// Placeholder - would track actual request rate
	return 100.0
}

func getResponseTime() float64 {
	// Placeholder - would track actual response times
	return 50.0
}

func getErrorRate() float64 {
	// Placeholder - would track actual error rates
	return 0.01
}

func generateNodeID() string {
	// Generate a unique node ID
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}