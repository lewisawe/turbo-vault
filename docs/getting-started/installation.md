# Installation Guide

## System Requirements

### Minimum Requirements
- **CPU**: 1 core
- **RAM**: 1GB
- **Storage**: 10GB SSD
- **Network**: HTTPS access to control plane

### Recommended Requirements
- **CPU**: 2+ cores
- **RAM**: 4GB
- **Storage**: 50GB SSD
- **Network**: Dedicated network interface

## Installation Methods

### Docker Installation

```bash
# Pull latest image
docker pull keyvault/agent:latest

# Create configuration
mkdir -p /etc/keyvault
cat > /etc/keyvault/config.yaml << EOF
server:
  port: 8080
  tls:
    cert_file: /certs/server.pem
    key_file: /certs/server-key.pem

storage:
  type: file
  path: /data/vault

control_plane:
  endpoint: https://your-control-plane.com
  auth_token: ${KEYVAULT_TOKEN}
EOF

# Run container
docker run -d \
  --name keyvault-agent \
  --restart unless-stopped \
  -v /etc/keyvault:/config:ro \
  -v /var/lib/keyvault:/data \
  -v /etc/ssl/keyvault:/certs:ro \
  -p 8080:8080 \
  keyvault/agent:latest
```

### Native Installation

#### Ubuntu/Debian
```bash
# Add repository
curl -fsSL https://packages.keyvault.dev/gpg | sudo apt-key add -
echo "deb https://packages.keyvault.dev/apt stable main" | sudo tee /etc/apt/sources.list.d/keyvault.list

# Install
sudo apt update
sudo apt install keyvault-agent

# Configure
sudo systemctl enable keyvault-agent
sudo systemctl start keyvault-agent
```

#### CentOS/RHEL
```bash
# Add repository
sudo tee /etc/yum.repos.d/keyvault.repo << EOF
[keyvault]
name=KeyVault Repository
baseurl=https://packages.keyvault.dev/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.keyvault.dev/gpg
EOF

# Install
sudo yum install keyvault-agent

# Configure
sudo systemctl enable keyvault-agent
sudo systemctl start keyvault-agent
```

### Kubernetes Installation

```bash
# Add Helm repository
helm repo add keyvault https://charts.keyvault.dev
helm repo update

# Install with Helm
helm install keyvault-agent keyvault/agent \
  --set config.controlPlane.endpoint=https://your-control-plane.com \
  --set config.controlPlane.token=your-token \
  --set persistence.enabled=true \
  --set persistence.size=50Gi
```

## Post-Installation

### Verify Installation
```bash
# Check service status
systemctl status keyvault-agent

# Test API endpoint
curl -k https://localhost:8080/health

# Check logs
journalctl -u keyvault-agent -f
```

### Initial Configuration
```bash
# Register with control plane
keyvault-cli register \
  --endpoint https://your-control-plane.com \
  --token <registration-token>

# Create first policy
keyvault-cli policies create \
  --name default \
  --path "/*" \
  --actions "read,write"
```
