# Comprehensive Deployment Guide

This guide provides detailed instructions for deploying Vault Agent across different platforms and environments, from development to production-scale deployments.

## Table of Contents

1. [Overview](#overview)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Native Installation](#native-installation)
5. [Cloud Provider Deployments](#cloud-provider-deployments)
6. [High Availability Setup](#high-availability-setup)
7. [Security Hardening](#security-hardening)
8. [Monitoring and Observability](#monitoring-and-observability)
9. [Backup and Disaster Recovery](#backup-and-disaster-recovery)
10. [Troubleshooting](#troubleshooting)

## Overview

Vault Agent can be deployed in various configurations depending on your requirements:

- **Development**: Single container or binary for local development
- **Staging**: Multi-container setup with external databases
- **Production**: High-availability cluster with load balancing
- **Enterprise**: Multi-region deployment with disaster recovery

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- Memory: 4GB RAM
- Storage: 20GB SSD
- Network: 1Gbps

**Recommended Production:**
- CPU: 4+ cores
- Memory: 8GB+ RAM
- Storage: 100GB+ SSD with IOPS 3000+
- Network: 10Gbps with redundancy

## Docker Deployment

### Quick Start

```bash
# Pull the latest image
docker pull vaultagent/vault-agent:latest

# Run with default configuration
docker run -d \
  --name vault-agent \
  -p 8200:8200 \
  -p 8080:8080 \
  -v vault-data:/data \
  -e VAULT_AGENT_LOG_LEVEL=info \
  vaultagent/vault-agent:latest
```

### Production Docker Setup

Create a production-ready Docker Compose configuration:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  vault-agent:
    image: vaultagent/vault-agent:1.0.0
    container_name: vault-agent
    ports:
      - "8200:8200"  # API port
      - "8080:8080"  # Web interface
      - "8201:8201"  # Metrics port
    volumes:
      - vault-data:/data
      - vault-config:/config:ro
      - vault-logs:/logs
      - vault-backups:/backups
    environment:
      # Core Configuration
      - VAULT_AGENT_LOG_LEVEL=info
      - VAULT_AGENT_LOG_FORMAT=json
      - VAULT_AGENT_HTTP_PORT=8200
      - VAULT_AGENT_WEB_PORT=8080
      - VAULT_AGENT_METRICS_PORT=8201
      
      # Storage Configuration
      - VAULT_AGENT_STORAGE_TYPE=postgresql
      - VAULT_AGENT_STORAGE_CONNECTION_STRING=postgres://vault:${DB_PASSWORD}@postgres:5432/vault?sslmode=require
      
      # Cache Configuration
      - VAULT_AGENT_CACHE_TYPE=redis
      - VAULT_AGENT_CACHE_CONNECTION_STRING=redis://redis:6379/0
      
      # Encryption Configuration
      - VAULT_AGENT_ENCRYPTION_KEY_FILE=/config/master.key
      - VAULT_AGENT_ENCRYPTION_KEY_ROTATION_INTERVAL=30d
      
      # Control Plane Configuration
      - VAULT_AGENT_CONTROL_PLANE_URL=https://api.vaultagent.com
      - VAULT_AGENT_CONTROL_PLANE_CERT_FILE=/config/client.crt
      - VAULT_AGENT_CONTROL_PLANE_KEY_FILE=/config/client.key
      
      # Backup Configuration
      - VAULT_AGENT_BACKUP_ENABLED=true
      - VAULT_AGENT_BACKUP_SCHEDULE=0 2 * * *
      - VAULT_AGENT_BACKUP_RETENTION_DAYS=30
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8200/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - vault-network

  postgres:
    image: postgres:15-alpine
    container_name: vault-postgres
    environment:
      - POSTGRES_DB=vault
      - POSTGRES_USER=vault
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault -d vault"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - vault-network

  redis:
    image: redis:7-alpine
    container_name: vault-redis
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    networks:
      - vault-network

  nginx:
    image: nginx:alpine
    container_name: vault-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - vault-agent
    restart: unless-stopped
    networks:
      - vault-network

volumes:
  vault-data:
    driver: local
  vault-config:
    driver: local
  vault-logs:
    driver: local
  vault-backups:
    driver: local
  postgres-data:
    driver: local
  redis-data:
    driver: local

networks:
  vault-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Environment Configuration

Create a `.env` file for sensitive configuration:

```bash
# .env
DB_PASSWORD=your-secure-database-password
REDIS_PASSWORD=your-secure-redis-password
VAULT_AGENT_API_KEY=your-api-key
VAULT_AGENT_JWT_SECRET=your-jwt-secret
```

### SSL/TLS Configuration

Create an nginx configuration for SSL termination:

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream vault_agents {
        least_conn;
        server vault-agent:8200 max_fails=3 fail_timeout=30s;
    }

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name vault.yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name vault.yourdomain.com;

        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Security Headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;

        # API Proxy
        location /api/ {
            proxy_pass http://vault_agents;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 5s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
            
            # Health check
            proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
        }

        # Web Interface
        location / {
            proxy_pass http://vault-agent:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health Check Endpoint
        location /health {
            access_log off;
            proxy_pass http://vault_agents/health;
        }

        # Metrics Endpoint (restrict access)
        location /metrics {
            allow 10.0.0.0/8;
            allow 172.16.0.0/12;
            allow 192.168.0.0/16;
            deny all;
            proxy_pass http://vault-agent:8201/metrics;
        }
    }
}
```

### Docker Security Hardening

Run containers with security best practices:

```bash
# Create non-root user
docker run -d \
  --name vault-agent \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /var/run:rw,noexec,nosuid,size=100m \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add SETGID \
  --cap-add SETUID \
  --security-opt no-new-privileges:true \
  --security-opt apparmor:docker-default \
  -p 8200:8200 \
  -v vault-data:/data \
  -v vault-config:/config:ro \
  vaultagent/vault-agent:latest
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.20+
- Helm 3.8+
- kubectl configured
- Persistent Volume support
- Ingress controller (nginx, traefik, etc.)

### Helm Chart Installation

#### Add Repository

```bash
helm repo add vault-agent https://charts.vaultagent.com
helm repo update
```

#### Development Installation

```bash
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --set replicaCount=1 \
  --set persistence.enabled=false \
  --set postgresql.enabled=true \
  --set redis.enabled=false
```

#### Production Installation

Create production values file:

```yaml
# values-production.yaml
replicaCount: 3

image:
  repository: vaultagent/vault-agent
  tag: "1.0.0"
  pullPolicy: IfNotPresent

nameOverride: ""
fullnameOverride: ""

serviceAccount:
  create: true
  annotations: {}
  name: ""

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8201"
  prometheus.io/path: "/metrics"

podSecurityContext:
  fsGroup: 65532
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL

service:
  type: ClusterIP
  port: 8200
  targetPort: http
  annotations: {}

ingress:
  enabled: true
  className: "nginx"
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: vault.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vault-agent-tls
      hosts:
        - vault.yourdomain.com

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

nodeSelector: {}

tolerations: []

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - vault-agent
        topologyKey: kubernetes.io/hostname

persistence:
  enabled: true
  storageClass: "fast-ssd"
  accessMode: ReadWriteOnce
  size: 50Gi

postgresql:
  enabled: true
  auth:
    postgresPassword: "secure-postgres-password"
    username: "vault"
    password: "secure-vault-password"
    database: "vault"
  primary:
    persistence:
      enabled: true
      size: 100Gi
      storageClass: "fast-ssd"
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 1Gi

redis:
  enabled: true
  auth:
    enabled: true
    password: "secure-redis-password"
  master:
    persistence:
      enabled: true
      size: 20Gi
      storageClass: "fast-ssd"
    resources:
      limits:
        cpu: 500m
        memory: 1Gi
      requests:
        cpu: 250m
        memory: 512Mi

config:
  server:
    log_level: "info"
    log_format: "json"
    http_port: 8200
    web_port: 8080
    metrics_port: 8201
  
  storage:
    type: "postgresql"
    connection_string: "postgres://vault:secure-vault-password@vault-agent-postgresql:5432/vault?sslmode=require"
  
  cache:
    type: "redis"
    connection_string: "redis://:secure-redis-password@vault-agent-redis-master:6379/0"
  
  encryption:
    key_manager:
      type: "kubernetes_secret"
      kubernetes_secret:
        secret_name: "vault-agent-encryption-key"
        key_name: "master.key"
  
  backup:
    enabled: true
    schedule: "0 2 * * *"
    retention:
      days: 30
      max_backups: 100
    destinations:
      - type: "s3"
        s3:
          bucket: "vault-agent-backups"
          region: "us-west-2"
          encryption: true

monitoring:
  enabled: true
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
      interval: 30s
      scrapeTimeout: 10s
  grafana:
    enabled: true
    dashboards:
      enabled: true

networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress-nginx
      ports:
      - protocol: TCP
        port: 8200
    - from:
      - namespaceSelector:
          matchLabels:
            name: monitoring
      ports:
      - protocol: TCP
        port: 8201

podDisruptionBudget:
  enabled: true
  minAvailable: 2

backup:
  enabled: true
  schedule: "0 2 * * *"
  retention: 30
  destinations:
    - type: s3
      bucket: vault-agent-backups
      region: us-west-2
```

Install with production values:

```bash
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --values values-production.yaml \
  --wait --timeout=15m
```

### Kubernetes Operator Deployment

The Vault Agent Operator provides advanced lifecycle management:

```bash
# Install the operator
kubectl apply -f https://github.com/vault-agent/operator/releases/latest/download/operator.yaml

# Wait for operator to be ready
kubectl wait --for=condition=available --timeout=300s deployment/vault-agent-operator -n vault-agent-system
```

Create a VaultAgent custom resource:

```yaml
# vault-agent-instance.yaml
apiVersion: vault-agent.io/v1
kind: VaultAgent
metadata:
  name: production-vault
  namespace: vault-agent
spec:
  replicas: 3
  
  image:
    repository: vaultagent/vault-agent
    tag: "1.0.0"
  
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 1000m
      memory: 2Gi
  
  storage:
    type: postgresql
    postgresql:
      host: postgres.vault-agent.svc.cluster.local
      port: 5432
      database: vault
      username: vault
      passwordSecret:
        name: postgres-credentials
        key: password
      sslMode: require
  
  cache:
    type: redis
    redis:
      host: redis.vault-agent.svc.cluster.local
      port: 6379
      database: 0
      passwordSecret:
        name: redis-credentials
        key: password
  
  encryption:
    keyManager:
      type: kubernetes_secret
      kubernetesSecret:
        secretName: vault-encryption-key
        keyName: master.key
  
  backup:
    enabled: true
    schedule: "0 2 * * *"
    retention:
      days: 30
      maxBackups: 100
    destinations:
      - type: s3
        s3:
          bucket: vault-agent-backups
          region: us-west-2
          credentialsSecret:
            name: aws-credentials
            accessKeyKey: access-key
            secretKeyKey: secret-key
  
  monitoring:
    enabled: true
    prometheus:
      enabled: true
      serviceMonitor: true
  
  ingress:
    enabled: true
    className: nginx
    host: vault.yourdomain.com
    tls:
      enabled: true
      secretName: vault-agent-tls
  
  networkPolicy:
    enabled: true
  
  podDisruptionBudget:
    enabled: true
    minAvailable: 2
  
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vault-agent
          topologyKey: kubernetes.io/hostname
```

Apply the custom resource:

```bash
kubectl apply -f vault-agent-instance.yaml
```

### Manual Kubernetes Deployment

For environments without Helm or the operator:

```bash
# Create namespace
kubectl create namespace vault-agent

# Apply all manifests
kubectl apply -f deployments/kubernetes/namespace.yaml
kubectl apply -f deployments/kubernetes/configmap.yaml
kubectl apply -f deployments/kubernetes/secret.yaml
kubectl apply -f deployments/kubernetes/deployment.yaml
kubectl apply -f deployments/kubernetes/service.yaml
kubectl apply -f deployments/kubernetes/ingress.yaml
```

## Native Installation

### Linux Package Installation

#### Ubuntu/Debian

```bash
# Add repository
curl -fsSL https://packages.vaultagent.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/vaultagent-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/vaultagent-archive-keyring.gpg] https://packages.vaultagent.com/apt stable main" | sudo tee /etc/apt/sources.list.d/vaultagent.list

# Update package list
sudo apt update

# Install Vault Agent
sudo apt install vault-agent

# Enable and start service
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

#### RHEL/CentOS/Fedora

```bash
# Add repository
sudo tee /etc/yum.repos.d/vaultagent.repo > /dev/null <<EOF
[vaultagent]
name=Vault Agent Repository
baseurl=https://packages.vaultagent.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.vaultagent.com/gpg
EOF

# Install Vault Agent
sudo dnf install vault-agent  # or yum install vault-agent

# Enable and start service
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

### Binary Installation

```bash
# Download binary for your platform
VAULT_AGENT_VERSION="1.0.0"
PLATFORM="linux-amd64"  # or linux-arm64, darwin-amd64, darwin-arm64, windows-amd64

wget "https://github.com/vault-agent/vault-agent/releases/download/v${VAULT_AGENT_VERSION}/vault-agent-${VAULT_AGENT_VERSION}-${PLATFORM}.tar.gz"

# Extract and install
tar -xzf "vault-agent-${VAULT_AGENT_VERSION}-${PLATFORM}.tar.gz"
sudo cp vault-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/vault-agent

# Create user and directories
sudo useradd --system --home /var/lib/vault-agent --shell /bin/false vault-agent
sudo mkdir -p /etc/vault-agent /var/lib/vault-agent /var/log/vault-agent
sudo chown vault-agent:vault-agent /var/lib/vault-agent /var/log/vault-agent
```

### Configuration

Create the main configuration file:

```yaml
# /etc/vault-agent/config.yaml
server:
  bind_address: "0.0.0.0:8200"
  web_bind_address: "0.0.0.0:8080"
  metrics_bind_address: "0.0.0.0:8201"
  log_level: "info"
  log_format: "json"
  log_file: "/var/log/vault-agent/vault-agent.log"
  
  tls:
    enabled: true
    cert_file: "/etc/vault-agent/tls/server.crt"
    key_file: "/etc/vault-agent/tls/server.key"
    min_version: "1.3"

storage:
  type: "postgresql"
  postgresql:
    connection_string: "postgres://vault:password@localhost:5432/vault?sslmode=require"
    max_connections: 20
    max_idle_connections: 5
    connection_max_lifetime: "1h"

cache:
  type: "redis"
  redis:
    connection_string: "redis://localhost:6379/0"
    max_connections: 10
    max_idle_connections: 5

encryption:
  key_manager:
    type: "file"
    file:
      key_file: "/etc/vault-agent/keys/master.key"
      rotation_interval: "30d"

authentication:
  methods:
    - "api_key"
    - "jwt"
    - "mtls"
  
  api_key:
    hash_rounds: 12
  
  jwt:
    secret_file: "/etc/vault-agent/keys/jwt.key"
    expiration: "24h"
  
  mtls:
    ca_file: "/etc/vault-agent/tls/ca.crt"
    verify_client_cert: true

policies:
  cache_size: 1000
  cache_ttl: "5m"
  evaluation_timeout: "10s"

backup:
  enabled: true
  schedule: "0 2 * * *"
  retention:
    days: 30
    max_backups: 100
  destinations:
    - type: "local"
      local:
        path: "/var/lib/vault-agent/backups"
    - type: "s3"
      s3:
        bucket: "vault-agent-backups"
        region: "us-west-2"
        encryption: true

monitoring:
  prometheus:
    enabled: true
    path: "/metrics"
  
  health_check:
    enabled: true
    path: "/health"
    interval: "30s"

control_plane:
  enabled: true
  url: "https://api.vaultagent.com"
  cert_file: "/etc/vault-agent/tls/client.crt"
  key_file: "/etc/vault-agent/tls/client.key"
  heartbeat_interval: "30s"
  offline_mode: true
```

### Systemd Service

Create systemd service file:

```ini
# /etc/systemd/system/vault-agent.service
[Unit]
Description=Vault Agent - Decentralized Key Management
Documentation=https://docs.vaultagent.com
After=network.target
Wants=network.target

[Service]
Type=simple
User=vault-agent
Group=vault-agent
ExecStart=/usr/local/bin/vault-agent server --config /etc/vault-agent/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/vault-agent /var/log/vault-agent
CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_CHOWN CAP_SETGID CAP_SETUID

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

### Windows Installation

1. Download the Windows installer: `vault-agent-1.0.0-windows-amd64.msi`
2. Run the installer as Administrator
3. Configure the service through the Windows Services console
4. Start the Vault Agent service

Alternatively, use PowerShell:

```powershell
# Download and install
Invoke-WebRequest -Uri "https://github.com/vault-agent/vault-agent/releases/download/v1.0.0/vault-agent-1.0.0-windows-amd64.zip" -OutFile "vault-agent.zip"
Expand-Archive -Path "vault-agent.zip" -DestinationPath "C:\Program Files\VaultAgent"

# Install as Windows service
& "C:\Program Files\VaultAgent\vault-agent.exe" service install --config "C:\Program Files\VaultAgent\config.yaml"

# Start service
Start-Service -Name "VaultAgent"
```

### macOS Installation

```bash
# Using Homebrew
brew tap vault-agent/tap
brew install vault-agent

# Or download binary
curl -LO "https://github.com/vault-agent/vault-agent/releases/download/v1.0.0/vault-agent-1.0.0-darwin-amd64.tar.gz"
tar -xzf vault-agent-1.0.0-darwin-amd64.tar.gz
sudo cp vault-agent /usr/local/bin/

# Create launch daemon
sudo tee /Library/LaunchDaemons/com.vaultagent.vault-agent.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vaultagent.vault-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vault-agent</string>
        <string>server</string>
        <string>--config</string>
        <string>/usr/local/etc/vault-agent/config.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>_vault-agent</string>
    <key>GroupName</key>
    <string>_vault-agent</string>
</dict>
</plist>
EOF

# Load and start service
sudo launchctl load /Library/LaunchDaemons/com.vaultagent.vault-agent.plist
```

## Cloud Provider Deployments

### AWS Deployment

#### EKS with RDS and ElastiCache

```bash
# Deploy infrastructure with Terraform
cd deployments/terraform/aws
terraform init
terraform plan -var="cluster_name=vault-agent-prod" -var="region=us-west-2"
terraform apply

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name vault-agent-prod

# Deploy Vault Agent
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --set postgresql.enabled=false \
  --set redis.enabled=false \
  --set config.storage.type=postgresql \
  --set config.storage.connectionString="$(terraform output -raw database_connection_string)" \
  --set config.cache.type=redis \
  --set config.cache.connectionString="$(terraform output -raw redis_connection_string)" \
  --set backup.destinations[0].type=s3 \
  --set backup.destinations[0].s3.bucket="$(terraform output -raw backup_bucket)" \
  --set backup.destinations[0].s3.region=us-west-2
```

#### EC2 with Auto Scaling

```bash
# Create launch template
aws ec2 create-launch-template \
  --launch-template-name vault-agent-template \
  --launch-template-data '{
    "ImageId": "ami-0c02fb55956c7d316",
    "InstanceType": "t3.medium",
    "SecurityGroupIds": ["sg-12345678"],
    "UserData": "'$(base64 -w 0 user-data.sh)'",
    "IamInstanceProfile": {
      "Name": "vault-agent-instance-profile"
    }
  }'

# Create auto scaling group
aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name vault-agent-asg \
  --launch-template LaunchTemplateName=vault-agent-template,Version=1 \
  --min-size 2 \
  --max-size 10 \
  --desired-capacity 3 \
  --vpc-zone-identifier "subnet-12345678,subnet-87654321" \
  --target-group-arns "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/vault-agent/1234567890123456"
```

### Azure Deployment

#### AKS with Azure Database and Redis Cache

```bash
# Deploy infrastructure
cd deployments/terraform/azure
terraform init
terraform plan -var="resource_group_name=vault-agent-prod" -var="location=West US 2"
terraform apply

# Configure kubectl
az aks get-credentials --resource-group vault-agent-prod --name vault-agent-cluster

# Deploy Vault Agent
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --values azure-values.yaml
```

#### Virtual Machine Scale Sets

```bash
# Create scale set
az vmss create \
  --resource-group vault-agent-prod \
  --name vault-agent-vmss \
  --image UbuntuLTS \
  --upgrade-policy-mode automatic \
  --instance-count 3 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --custom-data user-data.sh \
  --load-balancer vault-agent-lb
```

### Google Cloud Deployment

#### GKE with Cloud SQL and Memorystore

```bash
# Deploy infrastructure
cd deployments/terraform/gcp
terraform init
terraform plan -var="project_id=your-project-id" -var="region=us-central1"
terraform apply

# Configure kubectl
gcloud container clusters get-credentials vault-agent-cluster --region us-central1

# Deploy Vault Agent
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --values gcp-values.yaml
```

#### Compute Engine with Managed Instance Groups

```bash
# Create instance template
gcloud compute instance-templates create vault-agent-template \
  --machine-type=n1-standard-2 \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-ssd \
  --metadata-from-file startup-script=startup-script.sh \
  --service-account=vault-agent@your-project-id.iam.gserviceaccount.com \
  --scopes=cloud-platform

# Create managed instance group
gcloud compute instance-groups managed create vault-agent-group \
  --template=vault-agent-template \
  --size=3 \
  --zone=us-central1-a

# Set up auto scaling
gcloud compute instance-groups managed set-autoscaling vault-agent-group \
  --max-num-replicas=10 \
  --min-num-replicas=2 \
  --target-cpu-utilization=0.7 \
  --zone=us-central1-a
```

## High Availability Setup

### Load Balancer Configuration

#### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    daemon
    maxconn 4096
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend vault_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/vault-agent.pem
    redirect scheme https if !{ ssl_fc }
    default_backend vault_backend

backend vault_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    
    server vault1 10.0.1.10:8200 check
    server vault2 10.0.1.11:8200 check
    server vault3 10.0.1.12:8200 check
```

#### NGINX Load Balancer

```nginx
upstream vault_agents {
    least_conn;
    server 10.0.1.10:8200 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8200 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8200 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name vault.yourdomain.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        proxy_pass http://vault_agents;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }

    location /health {
        access_log off;
        proxy_pass http://vault_agents/health;
    }
}
```

### Database High Availability

#### PostgreSQL with Streaming Replication

```yaml
# Primary server configuration
# postgresql.conf
wal_level = replica
max_wal_senders = 3
max_replication_slots = 3
synchronous_commit = on
synchronous_standby_names = 'standby1,standby2'

# pg_hba.conf
host replication replicator 10.0.1.0/24 md5
```

#### Redis Cluster Configuration

```redis
# redis.conf
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
appendonly yes
```

### Monitoring High Availability

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'vault-agent'
    static_configs:
      - targets: ['10.0.1.10:8201', '10.0.1.11:8201', '10.0.1.12:8201']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'vault-agent-health'
    static_configs:
      - targets: ['10.0.1.10:8200', '10.0.1.11:8200', '10.0.1.12:8200']
    metrics_path: /health
    scrape_interval: 10s
```

## Security Hardening

### Network Security

#### Firewall Rules (iptables)

```bash
# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow Vault Agent API (port 8200)
iptables -A INPUT -p tcp --dport 8200 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8200 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p tcp --dport 8200 -s 192.168.0.0/16 -j ACCEPT

# Allow Vault Agent Web Interface (port 8080) - restrict to admin network
iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.0/24 -j ACCEPT

# Allow Prometheus metrics (port 8201) - restrict to monitoring network
iptables -A INPUT -p tcp --dport 8201 -s 10.0.2.0/24 -j ACCEPT

# Drop all other traffic
iptables -A INPUT -j DROP
```

#### Network Policies (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-agent-network-policy
  namespace: vault-agent
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: vault-agent
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8200
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8201
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: vault-agent
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
  - to: []
    ports:
    - protocol: TCP
      port: 443   # HTTPS outbound
    - protocol: UDP
      port: 53    # DNS
```

### TLS/SSL Configuration

#### Generate Self-Signed Certificates

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Vault Agent CA"

# Create server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=vault.yourdomain.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Create client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=vault-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

#### Let's Encrypt with Cert-Manager (Kubernetes)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Access Control

#### RBAC Configuration

```yaml
# vault-agent-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-agent
  namespace: vault-agent

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: vault-agent
  name: vault-agent
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-agent
  namespace: vault-agent
subjects:
- kind: ServiceAccount
  name: vault-agent
  namespace: vault-agent
roleRef:
  kind: Role
  name: vault-agent
  apiGroup: rbac.authorization.k8s.io
```

#### Pod Security Standards

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vault-agent
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: vault-agent
    image: vaultagent/vault-agent:1.0.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - CHOWN
        - SETGID
        - SETUID
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 1Gi
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "vault-agent-rules.yml"

scrape_configs:
  - job_name: 'vault-agent'
    static_configs:
      - targets: ['vault-agent:8201']
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 10s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "id": null,
    "title": "Vault Agent Dashboard",
    "tags": ["vault-agent"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_agent_http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(vault_agent_http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Active Secrets",
        "type": "singlestat",
        "targets": [
          {
            "expr": "vault_agent_secrets_total{status=\"active\"}",
            "legendFormat": "Active Secrets"
          }
        ]
      }
    ]
  }
}
```

### Alert Rules

```yaml
# vault-agent-rules.yml
groups:
- name: vault-agent
  rules:
  - alert: VaultAgentDown
    expr: up{job="vault-agent"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Vault Agent is down"
      description: "Vault Agent has been down for more than 1 minute"

  - alert: VaultAgentHighErrorRate
    expr: rate(vault_agent_http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High error rate in Vault Agent"
      description: "Error rate is {{ $value }} errors per second"

  - alert: VaultAgentHighLatency
    expr: histogram_quantile(0.95, rate(vault_agent_http_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency in Vault Agent"
      description: "95th percentile latency is {{ $value }} seconds"

  - alert: VaultAgentDiskSpaceLow
    expr: (node_filesystem_avail_bytes{mountpoint="/data"} / node_filesystem_size_bytes{mountpoint="/data"}) < 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Low disk space on Vault Agent"
      description: "Disk space is {{ $value | humanizePercentage }} full"
```

### Logging Configuration

#### Structured Logging

```yaml
# config.yaml
logging:
  level: info
  format: json
  output: stdout
  fields:
    service: vault-agent
    version: 1.0.0
    environment: production
```

#### Log Aggregation with Fluentd

```yaml
# fluentd.conf
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<match vault-agent.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name vault-agent
  type_name _doc
  
  <buffer>
    @type file
    path /var/log/fluentd-buffers/vault-agent.buffer
    flush_mode interval
    flush_interval 10s
  </buffer>
</match>
```

## Backup and Disaster Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup-vault-agent.sh

set -euo pipefail

# Configuration
BACKUP_DIR="/var/backups/vault-agent"
RETENTION_DAYS=30
S3_BUCKET="vault-agent-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="vault-agent-backup-${TIMESTAMP}"

# Create backup directory
mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"

# Backup database
echo "Backing up database..."
pg_dump -h localhost -U vault -d vault > "${BACKUP_DIR}/${BACKUP_NAME}/database.sql"

# Backup configuration
echo "Backing up configuration..."
cp -r /etc/vault-agent "${BACKUP_DIR}/${BACKUP_NAME}/config"

# Backup encryption keys
echo "Backing up encryption keys..."
cp -r /etc/vault-agent/keys "${BACKUP_DIR}/${BACKUP_NAME}/keys"

# Create archive
echo "Creating archive..."
tar -czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" -C "${BACKUP_DIR}" "${BACKUP_NAME}"
rm -rf "${BACKUP_DIR}/${BACKUP_NAME}"

# Upload to S3
echo "Uploading to S3..."
aws s3 cp "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" "s3://${S3_BUCKET}/${BACKUP_NAME}.tar.gz" --server-side-encryption AES256

# Cleanup old backups
echo "Cleaning up old backups..."
find "${BACKUP_DIR}" -name "*.tar.gz" -mtime +${RETENTION_DAYS} -delete
aws s3 ls "s3://${S3_BUCKET}/" | awk '{print $4}' | while read -r file; do
    if [[ $(aws s3api head-object --bucket "${S3_BUCKET}" --key "${file}" --query 'LastModified' --output text | xargs -I {} date -d {} +%s) -lt $(date -d "${RETENTION_DAYS} days ago" +%s) ]]; then
        aws s3 rm "s3://${S3_BUCKET}/${file}"
    fi
done

echo "Backup completed: ${BACKUP_NAME}.tar.gz"
```

### Disaster Recovery Procedure

```bash
#!/bin/bash
# restore-vault-agent.sh

set -euo pipefail

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/vault-agent-restore"

if [[ -z "${BACKUP_FILE}" ]]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

# Stop Vault Agent
echo "Stopping Vault Agent..."
systemctl stop vault-agent

# Extract backup
echo "Extracting backup..."
mkdir -p "${RESTORE_DIR}"
tar -xzf "${BACKUP_FILE}" -C "${RESTORE_DIR}"

# Restore database
echo "Restoring database..."
dropdb -h localhost -U postgres vault || true
createdb -h localhost -U postgres vault
psql -h localhost -U postgres -d vault < "${RESTORE_DIR}"/*/database.sql

# Restore configuration
echo "Restoring configuration..."
cp -r "${RESTORE_DIR}"/*/config/* /etc/vault-agent/

# Restore encryption keys
echo "Restoring encryption keys..."
cp -r "${RESTORE_DIR}"/*/keys/* /etc/vault-agent/keys/

# Set permissions
chown -R vault-agent:vault-agent /etc/vault-agent
chmod 600 /etc/vault-agent/keys/*

# Start Vault Agent
echo "Starting Vault Agent..."
systemctl start vault-agent

# Verify restoration
echo "Verifying restoration..."
sleep 10
curl -f http://localhost:8200/health || {
    echo "Health check failed!"
    exit 1
}

echo "Restoration completed successfully"
```

### Kubernetes Backup with Velero

```bash
# Install Velero
velero install \
    --provider aws \
    --plugins velero/velero-plugin-for-aws:v1.7.0 \
    --bucket vault-agent-velero-backups \
    --backup-location-config region=us-west-2 \
    --snapshot-location-config region=us-west-2

# Create backup schedule
velero schedule create vault-agent-daily \
    --schedule="0 2 * * *" \
    --include-namespaces vault-agent \
    --ttl 720h0m0s

# Manual backup
velero backup create vault-agent-manual \
    --include-namespaces vault-agent \
    --wait
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check service status
systemctl status vault-agent

# Check logs
journalctl -u vault-agent -f

# Check configuration
vault-agent config validate /etc/vault-agent/config.yaml

# Check permissions
ls -la /etc/vault-agent/
ls -la /var/lib/vault-agent/
```

#### Database Connection Issues

```bash
# Test database connectivity
psql -h localhost -U vault -d vault -c "SELECT 1;"

# Check database logs
tail -f /var/log/postgresql/postgresql-*.log

# Verify connection string
vault-agent config test-db --config /etc/vault-agent/config.yaml
```

#### High Memory Usage

```bash
# Check memory usage
ps aux | grep vault-agent
free -h

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full vault-agent server --config /etc/vault-agent/config.yaml

# Adjust memory limits
# In systemd service file:
# Environment="GOMEMLIMIT=1GiB"
```

#### SSL/TLS Issues

```bash
# Test SSL certificate
openssl s_client -connect localhost:8200 -servername vault.yourdomain.com

# Verify certificate chain
openssl verify -CAfile ca.crt server.crt

# Check certificate expiration
openssl x509 -in server.crt -noout -dates
```

### Performance Troubleshooting

#### High CPU Usage

```bash
# Profile CPU usage
go tool pprof http://localhost:8201/debug/pprof/profile

# Check for inefficient queries
# Enable query logging in PostgreSQL
# log_statement = 'all'
# log_min_duration_statement = 1000
```

#### Slow Response Times

```bash
# Check database performance
EXPLAIN ANALYZE SELECT * FROM secrets WHERE name = 'example';

# Monitor cache hit rates
redis-cli info stats | grep keyspace

# Check network latency
ping database-host
traceroute database-host
```

#### Storage Issues

```bash
# Check disk usage
df -h
du -sh /var/lib/vault-agent/*

# Check database size
psql -U vault -d vault -c "SELECT pg_size_pretty(pg_database_size('vault'));"

# Vacuum database
psql -U vault -d vault -c "VACUUM ANALYZE;"
```

### Debugging Tools

#### Health Check Script

```bash
#!/bin/bash
# health-check.sh

echo "=== Vault Agent Health Check ==="

# Service status
echo "Service Status:"
systemctl is-active vault-agent

# API health
echo "API Health:"
curl -s http://localhost:8200/health | jq .

# Database connectivity
echo "Database Connectivity:"
psql -h localhost -U vault -d vault -c "SELECT 1;" > /dev/null 2>&1 && echo "OK" || echo "FAILED"

# Cache connectivity
echo "Cache Connectivity:"
redis-cli ping > /dev/null 2>&1 && echo "OK" || echo "FAILED"

# Disk space
echo "Disk Space:"
df -h /var/lib/vault-agent

# Memory usage
echo "Memory Usage:"
ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem -C vault-agent
```

#### Log Analysis Script

```bash
#!/bin/bash
# analyze-logs.sh

LOG_FILE="/var/log/vault-agent/vault-agent.log"
HOURS=${1:-1}

echo "=== Log Analysis (Last ${HOURS} hours) ==="

# Error count
echo "Error Count:"
journalctl -u vault-agent --since="${HOURS} hours ago" | grep -c ERROR

# Top error messages
echo "Top Error Messages:"
journalctl -u vault-agent --since="${HOURS} hours ago" | grep ERROR | awk '{print $NF}' | sort | uniq -c | sort -nr | head -10

# Request rate
echo "Request Rate:"
journalctl -u vault-agent --since="${HOURS} hours ago" | grep "HTTP" | wc -l

# Response time analysis
echo "Response Time Analysis:"
journalctl -u vault-agent --since="${HOURS} hours ago" | grep "duration" | awk '{print $(NF-1)}' | sort -n | awk '
{
    times[NR] = $1
    sum += $1
}
END {
    if (NR > 0) {
        print "Average: " sum/NR "ms"
        print "Median: " times[int(NR/2)] "ms"
        print "95th percentile: " times[int(NR*0.95)] "ms"
    }
}'
```

---

*This comprehensive deployment guide covers all major deployment scenarios and operational considerations for Vault Agent. For additional support, consult the official documentation or contact support.*