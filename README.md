# KeyVault - Decentralized Key Management Platform

A self-hosted key management solution that gives developers full control over their secrets while providing centralized monitoring and automation capabilities.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Web Dashboard  │◄──►│  Control Plane   │◄──►│  Customer Vault │
│   (Frontend)    │    │   (Backend)      │    │    (Agent)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   PostgreSQL     │    │   Local Storage │
                       │   (Metadata)     │    │   (Encrypted)   │
                       └──────────────────┘    └─────────────────┘
```

## Core Components

- **Control Plane**: Central management service (metadata only)
- **Vault Agent**: Self-hosted component that stores actual secrets
- **Web Dashboard**: User interface for management and monitoring
- **CLI Tool**: Command-line interface for automation

## Key Features

- 🔐 Zero-trust architecture - secrets never leave customer infrastructure
- 📊 Real-time usage monitoring and analytics
- 🔄 Automated key rotation with customizable policies
- 🚨 Alert system for security events and policy violations
- 🔌 API-first design with extensive integrations
- 📦 Easy deployment via Docker, Kubernetes, or native binaries

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Git
- 1GB free disk space
- Ports 8080 and 3000 available

### One-Command Installation

```bash
# Clone and install
git clone <repository-url>
cd keyvault
./install.sh
```

### Manual Installation

```bash
# 1. Generate master key
mkdir -p config
openssl rand -hex 16 > config/master.key
chmod 600 config/master.key

# 2. Start services
docker compose up -d

# 3. Validate deployment
./validate-deployment.sh
```

### Access Points

- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8080/swagger/index.html  
- **Demo Login**: admin / admin123

### Using the CLI

```bash
# Build the CLI
cd vault-agent
go build -o vault-cli cmd/cli/main.go

# Configure CLI
echo "endpoint: http://localhost:8080" > .vault-cli.yaml
echo "token: demo-admin-token-2025" >> .vault-cli.yaml

# Test CLI
./vault-cli system status
./vault-cli secrets list
```

### Troubleshooting

If installation fails, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or run:

```bash
# Reset and try again
docker compose down -v
rm -rf data/ config/master.key
./install.sh
```