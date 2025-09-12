# Vault Agent Deployment Guide

This comprehensive guide covers all deployment options for Vault Agent across different environments and platforms.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Native Binary Installation](#native-binary-installation)
5. [Cloud Provider Deployments](#cloud-provider-deployments)
6. [CI/CD Integration](#cicd-integration)
7. [Configuration Management](#configuration-management)
8. [Monitoring and Observability](#monitoring-and-observability)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Quick Start

### Docker (Recommended for Development)

```bash
# Pull the latest image
docker pull vault-agent/vault-agent:latest

# Run with default configuration
docker run -d \
  --name vault-agent \
  -p 8200:8200 \
  vault-agent/vault-agent:latest
```

### Kubernetes (Recommended for Production)

```bash
# Add Helm repository
helm repo add vault-agent https://charts.vault-agent.com
helm repo update

# Install with default values
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace
```

## Docker Deployment

### Basic Docker Deployment

```bash
# Create configuration file
cat > vault-agent.yaml << EOF
server:
  bind_address: "0.0.0.0:8200"
  tls_cert_file: "/certs/tls.crt"
  tls_key_file: "/certs/tls.key"
  log_level: "info"

storage:
  type: "postgresql"
  connection_string: "postgres://user:pass@postgres:5432/vault_agent"

cache:
  type: "redis"
  connection_string: "redis://redis:6379"
EOF

# Run with custom configuration
docker run -d \
  --name vault-agent \
  -p 8200:8200 \
  -v $(pwd)/vault-agent.yaml:/etc/vault-agent/config.yaml:ro \
  -v $(pwd)/certs:/certs:ro \
  vault-agent/vault-agent:latest \
  server --config /etc/vault-agent/config.yaml
```

### Docker Compose Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  vault-agent:
    image: vault-agent/vault-agent:latest
    ports:
      - "8200:8200"
    volumes:
      - ./config:/etc/vault-agent:ro
      - ./certs:/certs:ro
      - vault-data:/var/lib/vault-agent
    environment:
      - VAULT_AGENT_CONFIG_PATH=/etc/vault-agent/config.yaml
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: vault_agent
      POSTGRES_USER: vault_agent
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  vault-data:
  postgres-data:
  redis-data:
```

### Multi-Architecture Support

Vault Agent Docker images support multiple architectures:

- `linux/amd64` (Intel/AMD 64-bit)
- `linux/arm64` (ARM 64-bit, Apple Silicon, AWS Graviton)

Docker automatically pulls the correct architecture for your platform.

## Kubernetes Deployment

### Helm Chart Installation

#### Prerequisites

- Kubernetes 1.20+
- Helm 3.8+
- Persistent Volume support (for production)

#### Basic Installation

```bash
# Add repository
helm repo add vault-agent https://charts.vault-agent.com
helm repo update

# Install with default values
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --wait
```

#### Production Installation

```bash
# Create values file for production
cat > production-values.yaml << EOF
replicaCount: 5

image:
  tag: "1.0.0"

resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 1000m
    memory: 2Gi

persistence:
  enabled: true
  size: 50Gi
  storageClass: "fast-ssd"

postgresql:
  enabled: true
  auth:
    database: vault_agent
    username: vault_agent
  primary:
    persistence:
      size: 100Gi

redis:
  enabled: true
  auth:
    enabled: true
  master:
    persistence:
      size: 20Gi

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true

backup:
  enabled: true
  schedule: "0 2 * * *"
  retention: 30

tls:
  enabled: true
  autoGenerate: false
  secretName: vault-agent-tls

networkPolicy:
  enabled: true

podDisruptionBudget:
  enabled: true
  minAvailable: 3
EOF

# Install production configuration
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --values production-values.yaml \
  --wait --timeout=15m
```

### Kubernetes Operator

The Vault Agent Operator provides advanced lifecycle management:

```bash
# Install the operator
kubectl apply -f https://github.com/vault-agent/operator/releases/latest/download/operator.yaml

# Create a VaultAgent resource
cat > vault-agent-instance.yaml << EOF
apiVersion: vault-agent.io/v1
kind: VaultAgent
metadata:
  name: production-vault
  namespace: vault-agent
spec:
  replicas: 3
  image:
    repository: vault-agent/vault-agent
    tag: "1.0.0"
  config:
    logLevel: info
    storage:
      type: postgresql
      connectionString: "postgres://user:pass@postgres:5432/vault_agent"
  resources:
    requests:
      cpu: 200m
      memory: 512Mi
    limits:
      cpu: 500m
      memory: 1Gi
  backup:
    enabled: true
    schedule: "0 2 * * *"
    retention: 30
  monitoring:
    enabled: true
EOF

kubectl apply -f vault-agent-instance.yaml
```

### Manual Kubernetes Deployment

For environments without Helm:

```bash
# Apply all manifests
kubectl apply -f deployments/kubernetes/namespace.yaml
kubectl apply -f deployments/kubernetes/deployment.yaml
kubectl apply -f deployments/kubernetes/service.yaml
```

## Native Binary Installation

### Linux (DEB/RPM Packages)

#### Ubuntu/Debian

```bash
# Download and install DEB package
wget https://github.com/vault-agent/vault-agent/releases/latest/download/vault-agent_1.0.0_amd64.deb
sudo dpkg -i vault-agent_1.0.0_amd64.deb

# Start and enable service
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

#### RHEL/CentOS/Fedora

```bash
# Download and install RPM package
wget https://github.com/vault-agent/vault-agent/releases/latest/download/vault-agent-1.0.0-1.x86_64.rpm
sudo rpm -i vault-agent-1.0.0-1.x86_64.rpm

# Start and enable service
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

### macOS

```bash
# Download and install PKG
wget https://github.com/vault-agent/vault-agent/releases/latest/download/vault-agent-1.0.0-darwin-amd64.pkg
sudo installer -pkg vault-agent-1.0.0-darwin-amd64.pkg -target /

# Start service
sudo launchctl load /Library/LaunchDaemons/com.vault-agent.vault-agent.plist
```

### Windows

1. Download `vault-agent-1.0.0-windows-amd64.zip`
2. Extract to `C:\Program Files\VaultAgent\`
3. Run `install-service.bat` as Administrator
4. Start service: `sc start VaultAgent`

### Binary Installation

```bash
# Download binary for your platform
wget https://github.com/vault-agent/vault-agent/releases/latest/download/vault-agent-1.0.0-linux-amd64.tar.gz
tar -xzf vault-agent-1.0.0-linux-amd64.tar.gz

# Install binary
sudo cp vault-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/vault-agent

# Create configuration directory
sudo mkdir -p /etc/vault-agent

# Create systemd service (Linux)
sudo tee /etc/systemd/system/vault-agent.service > /dev/null << EOF
[Unit]
Description=Vault Agent
After=network.target

[Service]
Type=simple
User=vault-agent
ExecStart=/usr/local/bin/vault-agent server --config /etc/vault-agent/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vault-agent
```

## Cloud Provider Deployments

### AWS (EKS + RDS + ElastiCache)

```bash
# Deploy infrastructure with Terraform
cd deployments/terraform/aws
terraform init
terraform plan -var="cluster_name=vault-agent-prod"
terraform apply

# Get kubeconfig
aws eks update-kubeconfig --region us-west-2 --name vault-agent-prod

# Deploy application
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --set postgresql.enabled=false \
  --set redis.enabled=false \
  --set config.storage.type=postgresql \
  --set config.storage.connectionString="$(terraform output -raw database_connection_string)" \
  --set config.cache.type=redis \
  --set config.cache.connectionString="$(terraform output -raw redis_connection_string)"
```

### Azure (AKS + PostgreSQL + Redis)

```bash
# Deploy infrastructure
cd deployments/terraform/azure
terraform init
terraform plan -var="resource_group_name=vault-agent-prod"
terraform apply

# Get kubeconfig
az aks get-credentials --resource-group vault-agent-prod --name vault-agent-cluster

# Deploy application
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --set postgresql.enabled=false \
  --set redis.enabled=false \
  --values azure-values.yaml
```

### Google Cloud (GKE + Cloud SQL + Memorystore)

```bash
# Deploy infrastructure
cd deployments/terraform/gcp
terraform init
terraform plan -var="project_id=your-project-id"
terraform apply

# Get kubeconfig
gcloud container clusters get-credentials vault-agent-cluster --region us-central1

# Deploy application
helm install vault-agent vault-agent/vault-agent \
  --namespace vault-agent \
  --create-namespace \
  --set postgresql.enabled=false \
  --set redis.enabled=false \
  --values gcp-values.yaml
```

## CI/CD Integration

### GitHub Actions

Use the provided workflow in `.github/workflows/deploy-vault-agent.yml`:

```yaml
# Trigger deployment
git push origin main  # Deploys to production
git push origin develop  # Deploys to staging
```

### Jenkins

Use the provided Jenkinsfile in `deployments/ci-cd/jenkins/Jenkinsfile`:

```groovy
// Configure Jenkins pipeline
pipeline {
    agent any
    // ... (see full Jenkinsfile)
}
```

### GitLab CI

Use the provided configuration in `deployments/ci-cd/gitlab-ci/.gitlab-ci.yml`:

```yaml
# Configure GitLab CI variables:
# - KUBE_CONFIG_STAGING
# - KUBE_CONFIG_PRODUCTION
# - SLACK_WEBHOOK_URL
```

### Azure DevOps

Use the provided pipeline in `deployments/ci-cd/azure-devops/azure-pipelines.yml`:

```yaml
# Configure service connections:
# - vault-agent-registry (Docker registry)
# - vault-agent-staging-k8s (Kubernetes)
# - vault-agent-production-k8s (Kubernetes)
```

## Configuration Management

### Environment-Specific Configurations

#### Development

```yaml
# values-dev.yaml
replicaCount: 1
resources:
  requests:
    cpu: 100m
    memory: 128Mi
persistence:
  enabled: false
postgresql:
  enabled: true
redis:
  enabled: false
```

#### Staging

```yaml
# values-staging.yaml
replicaCount: 2
resources:
  requests:
    cpu: 200m
    memory: 256Mi
persistence:
  enabled: true
  size: 10Gi
postgresql:
  enabled: true
redis:
  enabled: true
```

#### Production

```yaml
# values-production.yaml
replicaCount: 5
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 1000m
    memory: 2Gi
persistence:
  enabled: true
  size: 100Gi
  storageClass: fast-ssd
postgresql:
  enabled: true
  primary:
    persistence:
      size: 200Gi
redis:
  enabled: true
  master:
    persistence:
      size: 50Gi
backup:
  enabled: true
monitoring:
  enabled: true
```

### Configuration Validation

```bash
# Validate Helm chart
helm lint deployments/helm/vault-agent

# Dry-run installation
helm install vault-agent deployments/helm/vault-agent \
  --dry-run --debug \
  --values values-production.yaml

# Validate Kubernetes manifests
kubectl apply --dry-run=client -f deployments/kubernetes/
```

## Monitoring and Observability

### Prometheus Metrics

Vault Agent exposes metrics at `/metrics`:

```yaml
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vault-agent
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vault-agent
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

### Grafana Dashboard

Import the provided dashboard from `deployments/monitoring/grafana-dashboard.json`.

### Logging

Configure structured logging:

```yaml
config:
  server:
    log_level: info
    log_format: json
```

### Health Checks

- Health endpoint: `GET /health`
- Readiness endpoint: `GET /ready`
- Metrics endpoint: `GET /metrics`

## Security Considerations

### TLS Configuration

```yaml
tls:
  enabled: true
  secretName: vault-agent-tls
  # Or auto-generate certificates
  autoGenerate: true
```

### Network Policies

```yaml
networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: monitoring
      ports:
      - protocol: TCP
        port: 8200
```

### Pod Security Standards

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532

podSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
```

### RBAC

The Helm chart includes minimal RBAC permissions:

```yaml
rbac:
  create: true
  rules:
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["get", "list", "watch"]
```

## Troubleshooting

### Common Issues

#### Pod Startup Issues

```bash
# Check pod status
kubectl get pods -n vault-agent

# Check pod logs
kubectl logs -f deployment/vault-agent -n vault-agent

# Describe pod for events
kubectl describe pod <pod-name> -n vault-agent
```

#### Database Connection Issues

```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h <db-host> -U <username> -d <database>

# Check database logs
kubectl logs -f deployment/postgresql -n vault-agent
```

#### Performance Issues

```bash
# Check resource usage
kubectl top pods -n vault-agent

# Check metrics
curl http://localhost:8200/metrics

# Enable debug logging
helm upgrade vault-agent vault-agent/vault-agent \
  --set config.server.log_level=debug
```

### Debugging Commands

```bash
# Port forward for local access
kubectl port-forward svc/vault-agent 8200:8200 -n vault-agent

# Execute commands in pod
kubectl exec -it deployment/vault-agent -n vault-agent -- /bin/sh

# Check configuration
kubectl get configmap vault-agent-config -n vault-agent -o yaml
```

### Performance Tuning

#### Resource Optimization

```yaml
resources:
  requests:
    cpu: 500m      # Adjust based on load
    memory: 1Gi    # Minimum for production
  limits:
    cpu: 2000m     # Allow bursting
    memory: 4Gi    # Prevent OOM
```

#### Database Tuning

```yaml
postgresql:
  primary:
    extendedConfiguration: |
      max_connections = 200
      shared_buffers = 256MB
      effective_cache_size = 1GB
      work_mem = 4MB
```

#### Cache Configuration

```yaml
config:
  cache:
    type: redis
    ttl: 5m
    max_size: 10000
```

## Support and Documentation

- **Documentation**: https://docs.vault-agent.com
- **GitHub Issues**: https://github.com/vault-agent/vault-agent/issues
- **Community Forum**: https://community.vault-agent.com
- **Security Issues**: security@vault-agent.com

## License

Vault Agent is released under the MIT License. See LICENSE file for details.