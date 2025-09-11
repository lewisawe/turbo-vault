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

```bash
# Deploy vault agent
docker run -d --name keyvault-agent \
  -v ./config:/config \
  -v ./data:/data \
  -p 8080:8080 \
  keyvault/agent:latest

# Connect to control plane
keyvault-cli register --endpoint https://your-dashboard.com --token <registration-token>
```